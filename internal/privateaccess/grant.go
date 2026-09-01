package privateaccess

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/mint"
)

const (
	privateAccessCredentialClass = "private_access"
	privateAccessEnvironment     = "paperboat-private-access"
	privateAccessScope           = "private:access"
)

// GrantMinter is intentionally separate from the authorizer.  Hosts and edge
// adapters can request a fresh short-lived grant without receiving a durable
// bearer or connector secret.
type GrantMinter interface {
	MintGrant(context.Context, Request, time.Time) (string, error)
}

// MintGrantIssuer uses the repository's Ed25519 credential provider and its
// strict class/audience/expiry validation. The signed claims bind all fields
// needed by the private route authorizer; only the opaque signed value crosses
// this boundary and it is never persisted by privateaccess.
type MintGrantIssuer struct {
	provider *mint.Provider
	issuer   string
	clock    func() time.Time
}

func NewMintGrantIssuer(provider *mint.Provider, issuer string) (*MintGrantIssuer, error) {
	if provider == nil || strings.TrimSpace(issuer) == "" {
		return nil, fmt.Errorf("%w: mint provider and issuer are required", ErrInvalid)
	}
	return &MintGrantIssuer{provider: provider, issuer: issuer, clock: func() time.Time { return time.Now().UTC() }}, nil
}

func (g *MintGrantIssuer) SetClock(now func() time.Time) error {
	if g == nil || now == nil {
		return fmt.Errorf("%w: grant issuer clock is required", ErrInvalid)
	}
	g.clock = now
	return nil
}

func (g *MintGrantIssuer) MintGrant(_ context.Context, request Request, issuedAt time.Time) (string, error) {
	if g == nil || g.provider == nil {
		return "", fmt.Errorf("%w: grant issuer is unavailable", ErrIdentityUnavailable)
	}
	if err := request.Validate(); err != nil {
		return "", err
	}
	if issuedAt.IsZero() {
		issuedAt = g.clock().UTC()
	}
	issuedAt = issuedAt.UTC()
	if !request.ExpiresAt.After(issuedAt) || request.ExpiresAt.Sub(issuedAt) > mintPrivateAccessTTL {
		return "", fmt.Errorf("%w: grant expiry is out of bounds", ErrInvalid)
	}
	hash, err := request.Hash()
	if err != nil {
		return "", err
	}
	token, err := g.provider.SignCredential(mint.CredentialInput{
		Issuer: g.issuer, Audience: request.Audience, Subject: request.AccountID,
		JTI: request.Nonce, IssuedAt: issuedAt, ExpiresAt: request.ExpiresAt,
		CredentialClass: privateAccessCredentialClass, Scopes: []string{privateAccessScope},
		EnvironmentID: privateAccessEnvironment, AccountID: request.AccountID,
		MachineID: request.DeviceID, UserID: request.AccountID, SessionID: request.SessionID,
		OperationID: request.OperationID, ConnectorID: request.ConnectorID,
		ResourceKind: request.ResourceKind, ResourceID: request.ResourceID, RouteID: request.RouteID,
		Protocol: request.Protocol, AccessMode: "private", RouteGeneration: int64(request.RouteGeneration),
		CarrierSessionID: request.CarrierSessionID, ProcessGeneration: int64(request.ProcessGeneration), ConfigGeneration: int64(request.ConfigGeneration),
		InstallationGeneration: int64(request.InstallationGeneration), SessionGeneration: int64(request.SessionGeneration), AssignmentGeneration: int64(request.AssignmentGeneration),
		EdgeNodeID: request.EdgeNodeID, EdgeProcessEpoch: request.EdgeProcessEpoch,
		Method: request.Method, Host: request.Host, Path: request.Path,
		IdempotencyKey: request.IdempotencyKey, RequestID: request.RequestID, CorrelationID: request.CorrelationID,
		RequestHash: hash,
	})
	if err != nil {
		return "", fmt.Errorf("%w: sign private access grant", ErrIdentityUnavailable)
	}
	return token, nil
}

func (g *MintGrantIssuer) VerifyGrant(_ context.Context, token string, now time.Time) (Request, error) {
	if g == nil || g.provider == nil || strings.TrimSpace(token) == "" {
		return Request{}, ErrIdentityUnavailable
	}
	if now.IsZero() {
		now = g.clock().UTC()
	}
	claims, err := g.provider.VerifyCredential(token, g.issuer, privateAccessCredentialClass, now.UTC())
	if err != nil {
		return Request{}, ErrIdentityUnavailable
	}
	expiresAt := time.Unix(claims.ExpiresAt, 0).UTC()
	request := Request{
		AccountID: claims.AccountID, ResourceKind: claims.ResourceKind, ResourceID: claims.ResourceID,
		RouteID: claims.RouteID, Audience: claims.Audience, DeviceID: claims.MachineID,
		SessionID: claims.SessionID, ExpiresAt: expiresAt, Nonce: claims.JTI,
		OperationID: claims.OperationID, ConnectorID: claims.ConnectorID,
		CarrierSessionID: claims.CarrierSessionID, RouteGeneration: uint64(claims.RouteGeneration),
		InstallationGeneration: uint64(claims.InstallationGeneration), SessionGeneration: uint64(claims.SessionGeneration),
		ProcessGeneration: uint64(claims.ProcessGeneration), ConfigGeneration: uint64(claims.ConfigGeneration), AssignmentGeneration: uint64(claims.AssignmentGeneration),
		EdgeNodeID: claims.EdgeNodeID, EdgeProcessEpoch: claims.EdgeProcessEpoch,
		Protocol: claims.Protocol, Method: claims.Method, Host: claims.Host, Path: claims.Path,
		IdempotencyKey: claims.IdempotencyKey, RequestID: claims.RequestID, CorrelationID: claims.CorrelationID,
	}
	if err := request.Validate(); err != nil {
		return Request{}, ErrIdentityUnavailable
	}
	hash, err := request.Hash()
	if err != nil || hash != claims.RequestHash {
		return Request{}, ErrIdentityUnavailable
	}
	return request, nil
}

const mintPrivateAccessTTL = 2 * time.Minute
