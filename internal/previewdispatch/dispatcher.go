// Package previewdispatch delivers one canonical preview lease projection to
// the selected online machine. It owns transport and credential minting, but
// never owns lease persistence or readiness state.
package previewdispatch

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/canonicaljson"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
	"github.com/pinksaucepasta/paperboat-server/internal/mint"
	"github.com/pinksaucepasta/paperboat-server/internal/previewv1"
)

const (
	DefaultTimeout = 25 * time.Second
	maximumTimeout = 30 * time.Second
	maxResponse    = 32 << 10
	maxRequest     = 32 << 10
)

var (
	ErrInvalidConfiguration = errors.New("preview dispatcher configuration is invalid")
	ErrMachineOffline       = errors.New("preview dispatch machine is offline")
	ErrRouteUnavailable     = errors.New("preview dispatch route is unavailable")
)

// DispatchError is safe for callers and logs. It deliberately does not carry
// response bodies, URLs containing credentials, or bearer tokens.
type DispatchError struct {
	Code      string
	Uncertain bool
	Retryable bool
	Cause     error
}

func (e *DispatchError) Error() string {
	if e == nil || e.Code == "" {
		return "preview dispatch failed"
	}
	return "preview dispatch " + e.Code
}

func (e *DispatchError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

func (e *DispatchError) Is(target error) bool {
	other, ok := target.(*DispatchError)
	return ok && other != nil && e != nil && other.Code == e.Code && other.Uncertain == e.Uncertain
}

// UncertainOutcome lets the policy service classify transport failures without
// importing this transport package (which would create a package cycle).
func (e *DispatchError) UncertainOutcome() bool { return e != nil && e.Uncertain }

func IsUncertain(err error) bool {
	var dispatchErr *DispatchError
	return errors.As(err, &dispatchErr) && dispatchErr.Uncertain
}

// MachineRoute is returned only for a currently eligible helper route. The
// database resolver always returns an HTTPS base URL. Tests and controlled
// local adapters may use an HTTP base URL, but never a URL with userinfo,
// query, fragment, or a non-root path.
type MachineRoute struct {
	EnvironmentID string
	BaseURL       string
}

type MachineRouteResolver interface {
	ResolvePreviewDispatchRoute(context.Context, string, string) (MachineRoute, error)
}

type Config struct {
	Resolver MachineRouteResolver
	Signer   *mint.Provider
	Issuer   string
	Client   *http.Client
	Timeout  time.Duration
	Now      func() time.Time
	NewJTI   func() (string, error)
}

type Dispatcher struct {
	resolver MachineRouteResolver
	signer   *mint.Provider
	issuer   string
	client   *http.Client
	timeout  time.Duration
	now      func() time.Time
	newJTI   func() (string, error)
}

func New(config Config) (*Dispatcher, error) {
	if config.Resolver == nil || config.Signer == nil || strings.TrimSpace(config.Issuer) == "" {
		return nil, ErrInvalidConfiguration
	}
	timeout := config.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	if timeout > maximumTimeout {
		return nil, ErrInvalidConfiguration
	}
	now := config.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	newJTI := config.NewJTI
	if newJTI == nil {
		newJTI = randomJTI
	}
	client := config.Client
	if client == nil {
		client = &http.Client{}
	}
	// A redirect would forward a one-shot credential to an untrusted host.
	// Clone the client so a caller's reusable client is not mutated.
	transportClient := *client
	transportClient.Timeout = timeout
	transportClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return errors.New("preview dispatch redirect rejected")
	}
	return &Dispatcher{resolver: config.Resolver, signer: config.Signer, issuer: strings.TrimSpace(config.Issuer), client: &transportClient, timeout: timeout, now: now, newJTI: newJTI}, nil
}

// Dispatch validates the canonical projection, resolves the selected
// machine's active helper route, mints a short-lived operation-bound token,
// and makes one bounded HTTP request. It never changes lease state itself.
func (d *Dispatcher) Dispatch(ctx context.Context, request previewv1.DispatchRequest) (previewv1.DispatchOutcome, error) {
	if d == nil || ctx == nil {
		return previewv1.DispatchOutcome{}, ErrInvalidConfiguration
	}
	now := d.now().UTC()
	if err := request.Validate(now); err != nil {
		return previewv1.DispatchOutcome{}, err
	}
	if now.After(request.LeaseDeadline.UTC()) {
		return previewv1.DispatchOutcome{}, &DispatchError{Code: "lease_expired", Retryable: false, Cause: errLeaseExpired}
	}
	route, err := d.resolver.ResolvePreviewDispatchRoute(ctx, request.AccountID, request.OwnerDeviceID)
	if err != nil {
		if errors.Is(err, ErrMachineOffline) || errors.Is(err, ErrRouteUnavailable) || errors.Is(err, sql.ErrNoRows) {
			return previewv1.DispatchOutcome{}, &DispatchError{Code: "machine_unavailable", Retryable: true, Cause: err}
		}
		return previewv1.DispatchOutcome{}, uncertainDispatchError("route_resolution_failed", err)
	}
	endpoint, err := dispatchEndpoint(route.BaseURL)
	if err != nil {
		return previewv1.DispatchOutcome{}, &DispatchError{Code: "route_unavailable", Retryable: true, Cause: err}
	}
	expiresAt := now.Add(2 * time.Minute)
	if request.LeaseDeadline.Before(expiresAt) {
		expiresAt = request.LeaseDeadline.UTC()
	}
	if !expiresAt.After(now) {
		return previewv1.DispatchOutcome{}, &DispatchError{Code: "lease_expired", Retryable: false, Cause: errLeaseExpired}
	}
	jti, err := d.newJTI()
	if err != nil || strings.TrimSpace(jti) == "" {
		return previewv1.DispatchOutcome{}, &DispatchError{Code: "credential_mint_failed", Uncertain: false, Retryable: true, Cause: err}
	}
	userDeadline := utcTime(request.UserDeadline)
	token, err := d.signer.SignCredential(mint.CredentialInput{
		Issuer: d.issuer, Audience: "paperboat-machine", Subject: request.ActorID, JTI: jti,
		IssuedAt: now, ExpiresAt: expiresAt, CredentialClass: "preview_launch", Scopes: []string{"preview:launch"},
		EnvironmentID: route.EnvironmentID, AccountID: request.AccountID, MachineID: request.OwnerDeviceID,
		UserID: request.ActorID, ActorID: request.ActorID, OperationID: request.OperationID,
		PreviewID: request.PreviewID, OwnerSessionID: request.OwnerSessionID,
		IdempotencyKey: request.IdempotencyKey, RequestID: request.RequestID, CorrelationID: request.CorrelationID,
		TargetScheme: request.Target.Scheme, TargetAddress: request.Target.Address, AccessMode: request.AccessMode,
		Endpoint: request.Endpoint, LeaseDeadline: request.LeaseDeadline, UserDeadline: userDeadline,
		LeaseETag: request.LeaseETag, State: request.State, AllocationState: request.AllocationState,
		EdgeState: request.EdgeState, OriginState: request.OriginState, CreatedAt: request.CreatedAt,
		LastRenewedAt: request.LastRenewedAt, ExpectedGeneration: request.ExpectedGeneration, RequestHash: request.RequestHash,
	})
	if err != nil {
		return previewv1.DispatchOutcome{}, &DispatchError{Code: "credential_mint_failed", Retryable: false, Cause: err}
	}
	payload, err := json.Marshal(request)
	if err != nil || len(payload) > maxRequest {
		return previewv1.DispatchOutcome{}, &DispatchError{Code: "request_encoding_failed", Retryable: false, Cause: err}
	}
	requestCtx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()
	httpRequest, err := http.NewRequestWithContext(requestCtx, http.MethodPost, endpoint, strings.NewReader(string(payload)))
	if err != nil {
		return previewv1.DispatchOutcome{}, &DispatchError{Code: "request_encoding_failed", Retryable: false, Cause: err}
	}
	httpRequest.Header.Set("Authorization", "Bearer "+token)
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Accept", "application/json")
	httpRequest.Header.Set("Cache-Control", "no-store")
	response, err := d.client.Do(httpRequest)
	if err != nil {
		return previewv1.DispatchOutcome{}, classifyTransportError(requestCtx, err)
	}
	defer response.Body.Close()
	outcome, decodeErr := decodeOutcome(response.Body, request, response.StatusCode)
	if decodeErr != nil {
		return previewv1.DispatchOutcome{}, decodeErr
	}
	return outcome, nil
}

var errLeaseExpired = errors.New("preview lease deadline has passed")

func classifyTransportError(ctx context.Context, err error) error {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return uncertainDispatchError("timeout", err)
	}
	if errors.Is(err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled) {
		return uncertainDispatchError("canceled", err)
	}
	return uncertainDispatchError("transport_failed", err)
}

func decodeOutcome(reader io.Reader, request previewv1.DispatchRequest, status int) (previewv1.DispatchOutcome, error) {
	raw, err := io.ReadAll(io.LimitReader(reader, maxResponse+1))
	if err != nil || len(raw) > maxResponse {
		return previewv1.DispatchOutcome{}, &DispatchError{Code: "remote_invalid_response", Retryable: false}
	}
	if canonicaljson.RejectDuplicateFields(raw) != nil {
		return previewv1.DispatchOutcome{}, &DispatchError{Code: "remote_invalid_response", Retryable: false}
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var outcome previewv1.DispatchOutcome
	if err := decoder.Decode(&outcome); err != nil {
		if status >= 500 || status == http.StatusRequestTimeout || status == http.StatusTooManyRequests {
			return previewv1.DispatchOutcome{}, uncertainDispatchError("remote_uncertain", nil)
		}
		return previewv1.DispatchOutcome{}, &DispatchError{Code: "remote_invalid_response", Retryable: false}
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return previewv1.DispatchOutcome{}, &DispatchError{Code: "remote_invalid_response", Retryable: false}
	}
	if outcome.Schema != previewv1.Schema || outcome.Kind != previewv1.PreviewDispatchKind || outcome.PreviewID != request.PreviewID || outcome.OperationID != request.OperationID || outcome.Generation < request.ExpectedGeneration {
		return previewv1.DispatchOutcome{}, &DispatchError{Code: "remote_binding_mismatch", Retryable: false}
	}
	if outcome.State != "accepted" && outcome.State != "ready" && outcome.State != "failed" {
		return previewv1.DispatchOutcome{}, &DispatchError{Code: "remote_invalid_response", Retryable: false}
	}
	if status < 200 || status >= 300 {
		if outcome.State == "failed" {
			return outcome, nil
		}
		if status >= 500 || status == http.StatusRequestTimeout || status == http.StatusTooManyRequests {
			return previewv1.DispatchOutcome{}, uncertainDispatchError("remote_uncertain", nil)
		}
		return previewv1.DispatchOutcome{}, &DispatchError{Code: "remote_rejected", Retryable: false}
	}
	return outcome, nil
}

func uncertainDispatchError(code string, cause error) *DispatchError {
	return &DispatchError{Code: code, Uncertain: true, Retryable: true, Cause: errors.Join(previewv1.ErrDispatchUncertain, cause)}
}

func dispatchEndpoint(base string) (string, error) {
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	parsed, err := url.Parse(base)
	if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" && parsed.Path != "/" || parsed.RawPath != "" && parsed.RawPath != "/" {
		return "", ErrRouteUnavailable
	}
	parsed.Path = "/v1/preview-launches"
	parsed.RawPath = ""
	return parsed.String(), nil
}

func utcTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	result := value.UTC()
	return &result
}

func randomJTI() (string, error) {
	var raw [18]byte
	if _, err := io.ReadFull(rand.Reader, raw[:]); err != nil {
		return "", err
	}
	return "jti_preview_launch_" + base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

// DBMachineRouteResolver binds route eligibility to the selected user machine
// rather than merely looking up an environment route. This prevents a route
// for another online machine in the same environment from receiving a lease.
type DBMachineRouteResolver struct {
	DB *db.DB
}

func (r DBMachineRouteResolver) ResolvePreviewDispatchRoute(ctx context.Context, accountID, machineID string) (MachineRoute, error) {
	if r.DB == nil || strings.TrimSpace(accountID) == "" || strings.TrimSpace(machineID) == "" {
		return MachineRoute{}, ErrRouteUnavailable
	}
	machine, err := r.DB.Queries().GetUserMachineForUser(ctx, dbsqlc.GetUserMachineForUserParams{ID: machineID, UserID: accountID})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return MachineRoute{}, ErrRouteUnavailable
		}
		return MachineRoute{}, err
	}
	if machine.State != "online" || machine.SeatState != "occupied" || !machine.Online || machine.RevokedAt.Valid || machine.DeletedAt.Valid || machine.DisconnectedAt.Valid || !slices.Contains(machine.ConfiguredCapabilities, "preview_launch") || !slices.Contains(machine.ObservedCapabilities, "preview_launch") {
		return MachineRoute{}, ErrMachineOffline
	}
	route, err := r.DB.Queries().GetActiveHelperRouteForMachine(ctx, dbsqlc.GetActiveHelperRouteForMachineParams{MachineID: machineID, AccountID: accountID})
	if errors.Is(err, sql.ErrNoRows) {
		return MachineRoute{}, ErrRouteUnavailable
	}
	if err != nil {
		return MachineRoute{}, err
	}
	return MachineRoute{EnvironmentID: machine.EnvironmentID, BaseURL: "https://" + route.PublicHost}, nil
}
