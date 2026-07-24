package fly

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"

	"github.com/coreos/go-oidc/v3/oidc"
)

var ErrWorkloadIdentityInvalid = errors.New("fly workload identity is invalid")

type WorkloadIdentity struct {
	AppName     string
	MachineID   string
	MachineName string
	ImageDigest string
	TokenID     string
}

type WorkloadIdentityVerifier struct {
	issuer   string
	audience string
	client   *http.Client

	mu       sync.Mutex
	verifier *oidc.IDTokenVerifier
}

func NewWorkloadIdentityVerifier(orgSlug, audience string, client *http.Client) (*WorkloadIdentityVerifier, error) {
	orgSlug = strings.Trim(strings.TrimSpace(orgSlug), "/")
	audience = strings.TrimSpace(audience)
	if orgSlug == "" || strings.ContainsAny(orgSlug, "/?#") || audience == "" || client == nil {
		return nil, ErrWorkloadIdentityInvalid
	}
	return newWorkloadIdentityVerifier("https://oidc.fly.io/"+orgSlug, audience, client)
}

func newWorkloadIdentityVerifier(issuer, audience string, client *http.Client) (*WorkloadIdentityVerifier, error) {
	if strings.TrimSpace(issuer) == "" || strings.TrimSpace(audience) == "" || client == nil {
		return nil, ErrWorkloadIdentityInvalid
	}
	return &WorkloadIdentityVerifier{
		issuer:   issuer,
		audience: audience,
		client:   client,
	}, nil
}

func (v *WorkloadIdentityVerifier) Verify(ctx context.Context, rawToken string) (WorkloadIdentity, error) {
	if v == nil || len(rawToken) < 32 || len(rawToken) > 32<<10 {
		return WorkloadIdentity{}, ErrWorkloadIdentityInvalid
	}
	verifier, err := v.tokenVerifier(ctx)
	if err != nil {
		return WorkloadIdentity{}, ErrWorkloadIdentityInvalid
	}
	token, err := verifier.Verify(ctx, rawToken)
	if err != nil {
		return WorkloadIdentity{}, ErrWorkloadIdentityInvalid
	}
	var claims struct {
		AppName     string `json:"app_name"`
		MachineID   string `json:"machine_id"`
		MachineName string `json:"machine_name"`
		ImageDigest string `json:"image_digest"`
		TokenID     string `json:"jti"`
	}
	if token.Claims(&claims) != nil ||
		!boundedIdentityValue(claims.AppName, 1, 128) ||
		!boundedIdentityValue(claims.MachineID, 1, 128) ||
		!boundedIdentityValue(claims.MachineName, 1, 256) ||
		!boundedIdentityValue(claims.ImageDigest, 1, 256) ||
		!boundedIdentityValue(claims.TokenID, 8, 256) {
		return WorkloadIdentity{}, ErrWorkloadIdentityInvalid
	}
	return WorkloadIdentity{
		AppName: claims.AppName, MachineID: claims.MachineID, MachineName: claims.MachineName,
		ImageDigest: claims.ImageDigest, TokenID: claims.TokenID,
	}, nil
}

func (v *WorkloadIdentityVerifier) tokenVerifier(ctx context.Context) (*oidc.IDTokenVerifier, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.verifier != nil {
		return v.verifier, nil
	}
	provider, err := oidc.NewProvider(oidc.ClientContext(ctx, v.client), v.issuer)
	if err != nil {
		return nil, err
	}
	v.verifier = provider.Verifier(&oidc.Config{ClientID: v.audience})
	return v.verifier, nil
}

func boundedIdentityValue(value string, minimum, maximum int) bool {
	value = strings.TrimSpace(value)
	return len(value) >= minimum && len(value) <= maximum
}
