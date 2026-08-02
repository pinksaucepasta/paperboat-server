package codexsessions

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
	"github.com/pinksaucepasta/paperboat-server/internal/mint"
)

var (
	ErrInvalid               = errors.New("invalid codex session request")
	ErrNotFound              = errors.New("codex session not found")
	ErrLimitReached          = errors.New("codex session limit reached")
	ErrIdempotencyConflict   = errors.New("codex session idempotency conflict")
	ErrCapabilityUnavailable = errors.New("machine capability is unavailable")
	ErrMachineOffline        = errors.New("machine is offline")
)

const (
	DefaultLease       = 30 * time.Minute
	CredentialLifetime = 5 * time.Minute
)

type Service struct {
	db        *db.DB
	signer    *mint.Provider
	issuer    string
	maxActive int
	now       func() time.Time
}
type Session struct {
	ID                 string    `json:"id"`
	EnvironmentID      string    `json:"environment_id"`
	MachineID          string    `json:"machine_id"`
	State              string    `json:"state"`
	LeaseExpiresAt     time.Time `json:"lease_expires_at"`
	RemoteCodexVersion string    `json:"remote_codex_version,omitempty"`
	FailureCode        string    `json:"failure_code,omitempty"`
}
type Descriptor struct {
	Session             Session   `json:"session"`
	ManagementURL       string    `json:"management_url"`
	WebSocketURL        string    `json:"websocket_url"`
	ManageCredential    string    `json:"manage_credential"`
	ConnectCredential   string    `json:"connect_credential"`
	CredentialsExpireAt time.Time `json:"credentials_expire_at"`
}

func New(store *db.DB, signer *mint.Provider, issuer string, maxActive int) *Service {
	if maxActive <= 0 {
		maxActive = 4
	}
	return &Service{db: store, signer: signer, issuer: strings.TrimRight(issuer, "/"), maxActive: maxActive, now: func() time.Time { return time.Now().UTC() }}
}

func (s *Service) Create(ctx context.Context, userID, clientSessionID, environmentID, idempotencyKey string) (Session, error) {
	idempotencyKey = strings.TrimSpace(idempotencyKey)
	if userID == "" || clientSessionID == "" || environmentID == "" || idempotencyKey == "" || len(idempotencyKey) > 256 {
		return Session{}, ErrInvalid
	}
	hash := sha256.Sum256([]byte(environmentID))
	existing, err := s.db.Queries().GetCodexSessionByIdempotency(ctx, dbsqlc.GetCodexSessionByIdempotencyParams{CLIClientSessionID: clientSessionID, IdempotencyKey: idempotencyKey})
	if err == nil {
		if !equal(existing.RequestHash, hash[:]) {
			return Session{}, ErrIdempotencyConflict
		}
		return mapSession(existing), nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Session{}, err
	}
	resolved, err := s.db.Queries().ResolveCodexSessionEnvironment(ctx, dbsqlc.ResolveCodexSessionEnvironmentParams{EnvironmentID: environmentID, UserID: sql.NullString{String: userID, Valid: true}})
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, ErrNotFound
	}
	if err != nil {
		return Session{}, err
	}
	if !resolved.EdgeNodeID.Valid {
		return Session{}, ErrNotFound
	}
	if err := requireCodexCapability(resolved.Online, resolved.ConfiguredCapabilities, resolved.ObservedCapabilities); err != nil {
		return Session{}, err
	}
	now := s.now()
	var created dbsqlc.CodexSession
	err = s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := tx.Queries()
		if _, err := q.LockCodexSessionLimit(ctx, environmentID); err != nil {
			return err
		}
		count, err := q.CountActiveCodexSessions(ctx, dbsqlc.CountActiveCodexSessionsParams{UserID: userID, EnvironmentID: environmentID, Now: now})
		if err != nil {
			return err
		}
		if count >= int64(s.maxActive) {
			return ErrLimitReached
		}
		created, err = q.CreateCodexSession(ctx, dbsqlc.CreateCodexSessionParams{ID: newID("cdx"), EnvironmentID: environmentID, MachineID: resolved.MachineID, UserID: userID, CLIClientSessionID: clientSessionID, IdempotencyKey: idempotencyKey, RequestHash: hash[:], InstallationGeneration: resolved.InstallationGeneration, ConnectorGeneration: resolved.ConnectorGeneration, EdgePool: resolved.EdgePool, EdgeNodeID: resolved.EdgeNodeID.String, EdgeAssignmentHost: resolved.PublicHost, LeaseExpiresAt: now.Add(DefaultLease), Now: now})
		return err
	})
	if err != nil {
		return Session{}, err
	}
	return mapSession(created), nil
}

func (s *Service) Descriptor(ctx context.Context, userID, clientSessionID, id string) (Descriptor, error) {
	row, err := s.db.Queries().GetOwnedCodexSession(ctx, dbsqlc.GetOwnedCodexSessionParams{ID: id, UserID: userID, CLIClientSessionID: clientSessionID})
	if errors.Is(err, sql.ErrNoRows) {
		return Descriptor{}, ErrNotFound
	}
	if err != nil {
		return Descriptor{}, err
	}
	if row.State == "stopped" || row.State == "failed" || !row.LeaseExpiresAt.After(s.now()) {
		return Descriptor{}, ErrNotFound
	}
	capability, err := s.db.Queries().GetCodexSessionMachineCapability(ctx, dbsqlc.GetCodexSessionMachineCapabilityParams{MachineID: row.MachineID, EnvironmentID: row.EnvironmentID})
	if errors.Is(err, sql.ErrNoRows) {
		return Descriptor{}, ErrNotFound
	}
	if err != nil {
		return Descriptor{}, err
	}
	if err := requireCodexCapability(capability.Online, capability.ConfiguredCapabilities, capability.ObservedCapabilities); err != nil {
		return Descriptor{}, err
	}
	return s.descriptor(row)
}

func requireCodexCapability(online bool, configured, observed []string) error {
	if !contains(configured, "terminal_host") || !contains(configured, "codex_host") {
		return ErrCapabilityUnavailable
	}
	if !online || !contains(observed, "terminal_host") || !contains(observed, "codex_host") {
		return ErrMachineOffline
	}
	return nil
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
func (s *Service) Renew(ctx context.Context, userID, clientSessionID, id string) (Session, error) {
	now := s.now()
	row, err := s.db.Queries().RenewCodexSession(ctx, dbsqlc.RenewCodexSessionParams{LeaseExpiresAt: now.Add(DefaultLease), Now: now, ID: id, UserID: userID, CLIClientSessionID: clientSessionID})
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, ErrNotFound
	}
	return mapSession(row), err
}
func (s *Service) Stop(ctx context.Context, userID, clientSessionID, id string) error {
	_, err := s.db.Queries().StopCodexSession(ctx, dbsqlc.StopCodexSessionParams{Now: sql.NullTime{Time: s.now(), Valid: true}, ID: id, UserID: userID, CLIClientSessionID: clientSessionID})
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

func (s *Service) Worker(interval time.Duration) func(context.Context) error {
	if interval <= 0 {
		interval = time.Minute
	}
	return func(ctx context.Context) error {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-ticker.C:
				now := s.now()
				rows, err := s.db.Queries().ListExpiredCodexSessions(ctx, dbsqlc.ListExpiredCodexSessionsParams{Now: now, BatchSize: 100})
				if err != nil {
					return err
				}
				for _, row := range rows {
					if err := s.db.Queries().MarkExpiredCodexSessionStopped(ctx, dbsqlc.MarkExpiredCodexSessionStoppedParams{Now: sql.NullTime{Time: now, Valid: true}, ID: row.ID}); err != nil {
						return err
					}
				}
			}
		}
	}
}

func (s *Service) descriptor(row dbsqlc.CodexSession) (Descriptor, error) {
	if s.signer == nil || s.issuer == "" {
		return Descriptor{}, ErrInvalid
	}
	now := s.now()
	expires := now.Add(CredentialLifetime)
	base := mint.CredentialInput{Issuer: s.issuer, Audience: "paperboat-machine", Subject: row.UserID, IssuedAt: now, ExpiresAt: expires, EnvironmentID: row.EnvironmentID, MachineID: row.MachineID, UserID: row.UserID, CLIClientSessionID: row.CLIClientSessionID, SessionID: row.ID, InstallationGeneration: row.InstallationGeneration, ConnectorID: row.ConnectorID, ConnectorGeneration: row.ConnectorGeneration, EdgePool: row.EdgePool, EdgeNodeID: row.EdgeNodeID}
	base.JTI = newID("jti")
	base.CredentialClass = "codex_manage"
	base.Scopes = []string{"codex:prepare", "codex:browse", "codex:renew", "codex:stop"}
	manage, err := s.signer.SignCredential(base)
	if err != nil {
		return Descriptor{}, err
	}
	base.JTI = newID("jti")
	base.CredentialClass = "codex_connect"
	base.Scopes = []string{"codex:connect"}
	connect, err := s.signer.SignCredential(base)
	if err != nil {
		return Descriptor{}, err
	}
	httpsURL := "https://" + row.EdgeAssignmentHost + "/v1/codex-sessions/" + row.ID
	return Descriptor{Session: mapSession(row), ManagementURL: httpsURL, WebSocketURL: "wss://" + row.EdgeAssignmentHost + "/v1/codex-sessions/" + row.ID + "/ws", ManageCredential: manage, ConnectCredential: connect, CredentialsExpireAt: expires}, nil
}
func mapSession(r dbsqlc.CodexSession) Session {
	return Session{ID: r.ID, EnvironmentID: r.EnvironmentID, MachineID: r.MachineID, State: r.State, LeaseExpiresAt: r.LeaseExpiresAt, RemoteCodexVersion: r.RemoteCodexVersion.String, FailureCode: r.FailureCode.String}
}
func equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
func newID(prefix string) string {
	var value [16]byte
	_, _ = rand.Read(value[:])
	return prefix + "_" + hex.EncodeToString(value[:])
}
