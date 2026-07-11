package mint

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	ProofType     = "t3-cloud-mint+jwt"
	ProofScope    = "environment:connect"
	RevokeType    = "t3-cloud-revoke+jwt"
	RevokeScope   = "environment:revoke"
	MaxProofTTL   = 5 * time.Minute
	defaultMaxAge = 5 * time.Minute
)

type Key struct {
	ID         string
	PrivateKey ed25519.PrivateKey
}

type Provider struct {
	mu       sync.RWMutex
	activeID string
	keys     map[string]ed25519.PrivateKey
	maxAge   time.Duration
}

type ProofInput struct {
	Issuer          string
	EnvironmentID   string
	UserID          string
	ClientSessionID string
	JTI             string
	Nonce           string
	IssuedAt        time.Time
	ExpiresAt       time.Time
}

type RevocationInput struct {
	ProofInput
	SessionIDs []string
	Reason     string
}

func New(keys []Key, activeID string, maxAge time.Duration) (*Provider, error) {
	if maxAge <= 0 {
		maxAge = defaultMaxAge
	}
	provider := &Provider{activeID: strings.TrimSpace(activeID), keys: make(map[string]ed25519.PrivateKey), maxAge: maxAge}
	for _, key := range keys {
		id := strings.TrimSpace(key.ID)
		if id == "" || len(key.PrivateKey) != ed25519.PrivateKeySize {
			return nil, errors.New("mint keys require a non-empty id and Ed25519 private key")
		}
		if _, exists := provider.keys[id]; exists {
			return nil, fmt.Errorf("duplicate mint key id %q", id)
		}
		provider.keys[id] = append(ed25519.PrivateKey(nil), key.PrivateKey...)
	}
	if len(provider.keys) == 0 {
		return nil, errors.New("at least one mint key is required")
	}
	if _, ok := provider.keys[provider.activeID]; !ok {
		return nil, fmt.Errorf("active mint key %q is not published", provider.activeID)
	}
	return provider, nil
}

func NewEphemeral(maxAge time.Duration) (*Provider, error) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate mint key: %w", err)
	}
	return New([]Key{{ID: "development-ephemeral", PrivateKey: privateKey}}, "development-ephemeral", maxAge)
}

// ParseKeys accepts entries in the form kid:base64url(ed25519-seed-or-private-key).
func ParseKeys(specs []string, activeID string, maxAge time.Duration) (*Provider, error) {
	keys := make([]Key, 0, len(specs))
	for _, spec := range specs {
		id, encoded, ok := strings.Cut(strings.TrimSpace(spec), ":")
		if !ok {
			return nil, errors.New("mint signing keys must use kid:base64url format")
		}
		raw, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("decode mint key %q: %w", id, err)
		}
		if len(raw) == ed25519.SeedSize {
			raw = ed25519.NewKeyFromSeed(raw)
		}
		keys = append(keys, Key{ID: id, PrivateKey: ed25519.PrivateKey(raw)})
	}
	return New(keys, activeID, maxAge)
}

func (p *Provider) Sign(input ProofInput) (string, error) {
	if strings.TrimSpace(input.Issuer) == "" || strings.TrimSpace(input.EnvironmentID) == "" || strings.TrimSpace(input.UserID) == "" || strings.TrimSpace(input.ClientSessionID) == "" || strings.TrimSpace(input.JTI) == "" || strings.TrimSpace(input.Nonce) == "" {
		return "", errors.New("mint proof claims are incomplete")
	}
	issuedAt := input.IssuedAt.UTC()
	expiresAt := input.ExpiresAt.UTC()
	if !expiresAt.After(issuedAt) || expiresAt.Sub(issuedAt) > MaxProofTTL {
		return "", errors.New("mint proof lifetime must be positive and at most five minutes")
	}
	return p.signClaims(ProofType, map[string]any{
		"iss": input.Issuer, "aud": "t3-env:" + input.EnvironmentID, "sub": input.UserID,
		"jti": input.JTI, "iat": issuedAt.Unix(), "exp": expiresAt.Unix(),
		"environmentId": input.EnvironmentID, "clientSessionId": input.ClientSessionID,
		"nonce": input.Nonce, "scope": []string{ProofScope},
	})
}

func (p *Provider) SignRevocation(input RevocationInput) (string, error) {
	if strings.TrimSpace(input.Issuer) == "" || strings.TrimSpace(input.EnvironmentID) == "" || strings.TrimSpace(input.UserID) == "" || strings.TrimSpace(input.ClientSessionID) == "" || strings.TrimSpace(input.JTI) == "" || strings.TrimSpace(input.Nonce) == "" || strings.TrimSpace(input.Reason) == "" || len(input.SessionIDs) == 0 {
		return "", errors.New("revocation proof claims are incomplete")
	}
	issuedAt := input.IssuedAt.UTC()
	expiresAt := input.ExpiresAt.UTC()
	if !expiresAt.After(issuedAt) || expiresAt.Sub(issuedAt) > MaxProofTTL {
		return "", errors.New("revocation proof lifetime must be positive and at most five minutes")
	}
	return p.signClaims(RevokeType, map[string]any{
		"iss": input.Issuer, "aud": "t3-env:" + input.EnvironmentID, "sub": input.UserID,
		"jti": input.JTI, "iat": issuedAt.Unix(), "exp": expiresAt.Unix(),
		"environmentId": input.EnvironmentID, "clientSessionId": input.ClientSessionID,
		"nonce": input.Nonce, "scope": []string{RevokeScope}, "sessionIds": input.SessionIDs,
		"reason": input.Reason,
	})
}

func (p *Provider) signClaims(proofType string, claims map[string]any) (string, error) {
	p.mu.RLock()
	id := p.activeID
	privateKey := append(ed25519.PrivateKey(nil), p.keys[id]...)
	p.mu.RUnlock()
	header, err := json.Marshal(map[string]string{"alg": "EdDSA", "typ": proofType, "kid": id})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	unsigned := encode(header) + "." + encode(payload)
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, []byte(unsigned))), nil
}

func (p *Provider) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	p.mu.RLock()
	keys := make([]map[string]string, 0, len(p.keys))
	ids := make([]string, 0, len(p.keys))
	for id := range p.keys {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		privateKey := p.keys[id]
		publicKey := privateKey.Public().(ed25519.PublicKey)
		keys = append(keys, map[string]string{
			"kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "use": "sig", "kid": id,
			"x": base64.RawURLEncoding.EncodeToString(publicKey),
		})
	}
	maxAge := int(p.maxAge.Seconds())
	p.mu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", maxAge))
	_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
}

func encode(value []byte) string { return base64.RawURLEncoding.EncodeToString(value) }
