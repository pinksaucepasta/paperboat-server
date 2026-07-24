package controlplane

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
	"github.com/pinksaucepasta/paperboat-server/internal/secrets"
)

var ErrHostedBootstrapInvalid = errors.New("hosted bootstrap request is invalid")

type HostedBootstrap struct {
	SetupScriptRef    string     `json:"setup_script_ref"`
	SetupScript       string     `json:"setup_script"`
	SetupScriptSHA256 string     `json:"setup_script_sha256"`
	SourceUsername    string     `json:"source_username,omitempty"`
	SourcePassword    string     `json:"source_password,omitempty"`
	SourceExpiresAt   *time.Time `json:"source_expires_at,omitempty"`
}

type HostedSourceCredential struct {
	Username  string
	Password  string
	ExpiresAt time.Time
}

type HostedSourceCredentialIssuer interface {
	IssueHostedSourceCredential(context.Context, string, string) (HostedSourceCredential, error)
}

type HostedSourceCredentialIssuerFunc func(context.Context, string, string) (HostedSourceCredential, error)

func (f HostedSourceCredentialIssuerFunc) IssueHostedSourceCredential(ctx context.Context, userID, sourceURL string) (HostedSourceCredential, error) {
	return f(ctx, userID, sourceURL)
}

type HostedBootstrapService struct {
	store         *db.DB
	identities    *EnrollmentService
	encryptionKey string
	source        HostedSourceCredentialIssuer
}

func (s *HostedBootstrapService) SetSourceCredentialIssuer(issuer HostedSourceCredentialIssuer) {
	s.source = issuer
}

func NewHostedBootstrapService(store *db.DB, identities *EnrollmentService, encryptionKey string) *HostedBootstrapService {
	return &HostedBootstrapService{store: store, identities: identities, encryptionKey: encryptionKey}
}

func (s *HostedBootstrapService) Get(ctx context.Context, identityToken string, proof, body []byte, method, path string) (HostedBootstrap, error) {
	if s == nil || s.store == nil || s.identities == nil || s.encryptionKey == "" || string(body) != "{}" {
		return HostedBootstrap{}, ErrHostedBootstrapInvalid
	}
	identity, err := s.identities.VerifyHelperRequest(ctx, identityToken, proof, method, path, body)
	if err != nil {
		return HostedBootstrap{}, ErrHostedBootstrapInvalid
	}
	intent, err := s.store.Queries().GetHostedProjectSetupIntent(ctx, identity.EnvironmentID)
	if err != nil {
		return HostedBootstrap{}, ErrHostedBootstrapInvalid
	}
	ref := strings.TrimSpace(intent.SetupScriptRef)
	result := HostedBootstrap{}
	if s.source != nil {
		credential, credentialErr := s.source.IssueHostedSourceCredential(ctx, intent.UserID, intent.SourceUrl)
		if credentialErr != nil {
			return HostedBootstrap{}, ErrHostedBootstrapInvalid
		}
		if credential.Password != "" {
			if credential.Username != "x-access-token" || !credential.ExpiresAt.After(time.Now().UTC()) {
				return HostedBootstrap{}, ErrHostedBootstrapInvalid
			}
			expiresAt := credential.ExpiresAt.UTC()
			result.SourceUsername = credential.Username
			result.SourcePassword = credential.Password
			result.SourceExpiresAt = &expiresAt
		}
	}
	if ref == "" {
		return result, nil
	}
	revision, err := s.store.Queries().GetProjectSetupScriptCiphertext(ctx, dbsqlc.GetProjectSetupScriptCiphertextParams{
		ProjectID: intent.ProjectID, ID: ref,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return HostedBootstrap{}, ErrHostedBootstrapInvalid
	}
	if err != nil {
		return HostedBootstrap{}, err
	}
	script, err := secrets.Decrypt(s.encryptionKey, revision)
	if err != nil || len(script) > 64<<10 {
		return HostedBootstrap{}, ErrHostedBootstrapInvalid
	}
	digest := sha256.Sum256([]byte(script))
	result.SetupScriptRef = ref
	result.SetupScript = script
	result.SetupScriptSHA256 = hex.EncodeToString(digest[:])
	return result, nil
}
