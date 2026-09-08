package nativeprivateaccess

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/mint"
)

var ErrDenied = errors.New("native private access denied")
var ErrInvalid = errors.New("native private access request invalid")

type Target struct {
	AccountID          string `json:"account_id"`
	UserID             string `json:"user_id"`
	EnvironmentID      string `json:"environment_id"`
	MachineID          string `json:"machine_id"`
	AccessSessionID    string `json:"access_session_id"`
	ResourceKind       string `json:"resource_kind"`
	ResourceID         string `json:"resource_id"`
	ResourceGeneration int64  `json:"resource_generation"`
	RouteID            string `json:"route_id"`
	RouteGeneration    int64  `json:"route_generation"`
	TargetGeneration   int64  `json:"target_generation"`
	Protocol           string `json:"protocol"`
	TargetScheme       string `json:"target_scheme"`
	TargetAddress      string `json:"target_address"`
}
type Request struct{ AccountID, UserID, CLIClientSessionID, OperationID, ResourceKind, ResourceID, RouteID, Protocol, Selector string }
type Resolver interface {
	ResolveNativePrivate(context.Context, Request) (Target, error)
}
type Signer interface {
	SignCredential(mint.CredentialInput) (string, error)
}
type Service struct {
	Resolver Resolver
	Signer   Signer
	Issuer   string
	Now      func() time.Time
}

type Grant struct {
	Target     Target    `json:"target"`
	Credential string    `json:"credential"`
	ExpiresAt  time.Time `json:"expires_at"`
}

func (s Service) Issue(ctx context.Context, request Request) (Grant, error) {
	if ctx == nil || s.Resolver == nil || s.Signer == nil || s.Issuer == "" || request.OperationID == "" || len(request.Selector) > 256 || strings.ContainsAny(request.Selector, "\x00\r\n/\\") {
		return Grant{}, ErrInvalid
	}
	target, err := s.Resolver.ResolveNativePrivate(ctx, request)
	if err != nil || !matchesRequest(target, request) || !validTarget(target) {
		return Grant{}, ErrDenied
	}
	now := time.Now().UTC()
	if s.Now != nil {
		now = s.Now().UTC()
	}
	// JWT NumericDate is second-granular. Return the identical instant in the
	// stream binding so host comparison cannot reject a valid grant because the
	// JSON timestamp retained sub-second precision.
	expires := now.Add(5 * time.Minute).Truncate(time.Second)
	credential, err := s.Signer.SignCredential(mint.CredentialInput{Issuer: s.Issuer, Audience: "paperboat-machine", Subject: target.UserID, JTI: "native_private_" + request.OperationID, IssuedAt: now, ExpiresAt: expires, CredentialClass: "native_private", Scopes: []string{"private:native"}, EnvironmentID: target.EnvironmentID, AccountID: target.AccountID, MachineID: target.MachineID, UserID: target.UserID, CLIClientSessionID: request.CLIClientSessionID, AssignmentID: target.AccessSessionID, OperationID: request.OperationID, ResourceKind: target.ResourceKind, ResourceID: target.ResourceID, RouteID: target.RouteID, Protocol: target.Protocol, TargetScheme: target.TargetScheme, TargetAddress: target.TargetAddress, ExpectedGeneration: target.ResourceGeneration, RouteGeneration: target.RouteGeneration, TargetGeneration: target.TargetGeneration})
	if err != nil {
		return Grant{}, err
	}
	return Grant{Target: target, Credential: credential, ExpiresAt: expires}, nil
}

func (s Service) Revalidate(ctx context.Context, request Request, expected Target) error {
	current, err := s.Resolver.ResolveNativePrivate(ctx, request)
	if err != nil || current != expected || !matchesRequest(current, request) || !validTarget(current) {
		return ErrDenied
	}
	return nil
}
func matchesRequest(t Target, r Request) bool {
	if r.Selector != "" {
		return t.AccountID == r.AccountID && t.UserID == r.UserID && t.ResourceKind == "tunnel" && t.Protocol == "tcp"
	}
	return t.AccountID == r.AccountID && t.UserID == r.UserID && t.ResourceKind == r.ResourceKind && t.ResourceID == r.ResourceID && t.RouteID == r.RouteID && t.Protocol == r.Protocol
}
func validTarget(t Target) bool {
	host, port, err := net.SplitHostPort(t.TargetAddress)
	n, pe := strconv.ParseUint(port, 10, 16)
	scheme := t.Protocol == "http" && (t.TargetScheme == "http" || t.TargetScheme == "https" || t.TargetScheme == "h2c") || t.Protocol == "tcp" && t.TargetScheme == "tcp"
	return t.AccountID != "" && t.UserID != "" && t.EnvironmentID != "" && t.MachineID != "" && t.AccessSessionID != "" && (t.ResourceKind == "preview" || t.ResourceKind == "tunnel") && t.ResourceID != "" && t.RouteID != "" && t.ResourceGeneration > 0 && t.RouteGeneration > 0 && t.TargetGeneration > 0 && scheme && err == nil && pe == nil && n > 0 && (host == "127.0.0.1" || host == "::1")
}
