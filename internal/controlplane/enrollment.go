package controlplane

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
	"github.com/pinksaucepasta/paperboat-server/internal/mint"
	"github.com/pinksaucepasta/paperboat-server/internal/secrets"
)

var (
	ErrEnrollmentInvalid = errors.New("helper enrollment is invalid")
	ErrEnrollmentUsed    = errors.New("helper enrollment is unavailable")
)

type EnrollmentService struct {
	store         *db.DB
	signer        *mint.Provider
	audit         *audit.Writer
	issuer        string
	encryptionKey string
	clock         func() time.Time
}

type EnrollmentGrant struct {
	EnrollmentID string    `json:"enrollment_id"`
	HelperID     string    `json:"helper_id"`
	Credential   string    `json:"credential"`
	ExpiresAt    time.Time `json:"expires_at"`
}

type HelperIdentity struct {
	HelperID      string    `json:"helper_id"`
	EnvironmentID string    `json:"environment_id"`
	Credential    string    `json:"credential"`
	ExpiresAt     time.Time `json:"expires_at"`
}

type HelperReplacement struct {
	EnvironmentID       string `json:"environment_id"`
	HelperID            string `json:"helper_id"`
	ConnectorGeneration int64  `json:"connector_generation"`
}

// EnsureBootGrant returns no credential after the environment has an active
// helper. Before first enrollment it replays only an unexpired pending grant;
// expired grants are revoked and replaced under a fresh operation key.
func (s *EnrollmentService) EnsureBootGrant(ctx context.Context, actorID, operationPrefix, environmentID string, lifetime time.Duration) (EnrollmentGrant, error) {
	now := s.clock().UTC()
	if _, err := s.store.Queries().GetActiveControlHelperForEnvironment(ctx, environmentID); err == nil {
		return EnrollmentGrant{}, nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return EnrollmentGrant{}, err
	}
	if pending, err := s.store.Queries().GetPendingControlHelperEnrollmentForEnvironment(ctx, environmentID); err == nil && pending.ExpiresAt.After(now) {
		var requestHash [sha256.Size]byte
		if len(pending.RequestHash) != len(requestHash) {
			return EnrollmentGrant{}, ErrEnrollmentInvalid
		}
		copy(requestHash[:], pending.RequestHash)
		return s.replayGrant(pending, requestHash)
	} else if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return EnrollmentGrant{}, err
	}
	if _, err := s.store.Queries().RevokeExpiredControlHelperEnrollments(ctx, dbsqlc.RevokeExpiredControlHelperEnrollmentsParams{EnvironmentID: environmentID, Now: sql.NullTime{Time: now, Valid: true}}); err != nil {
		return EnrollmentGrant{}, err
	}
	return s.Issue(ctx, actorID, fmt.Sprintf("%s:%d", operationPrefix, now.Unix()), environmentID, lifetime)
}

func (s *EnrollmentService) VerifyActivityHeartbeat(ctx context.Context, identityToken string, proof, body []byte, environmentID, machineID string) error {
	claims, err := s.VerifyHelperRequest(ctx, identityToken, proof, http.MethodPost, "/api/machine/activity-heartbeat", body)
	if err != nil || claims.EnvironmentID != environmentID {
		return ErrHelperProof
	}
	owned, err := s.store.Queries().HostedHelperOwnsMachine(ctx, dbsqlc.HostedHelperOwnsMachineParams{HelperID: claims.HelperID, EnvironmentID: environmentID, MachineID: machineID})
	if err != nil || !owned {
		return ErrHelperProof
	}
	return nil
}

func NewEnrollmentService(store *db.DB, signer *mint.Provider, writer *audit.Writer, issuer, encryptionKey string) *EnrollmentService {
	return &EnrollmentService{store: store, signer: signer, audit: writer, issuer: strings.TrimRight(strings.TrimSpace(issuer), "/"), encryptionKey: encryptionKey, clock: func() time.Time { return time.Now().UTC() }}
}

func (s *EnrollmentService) Issue(ctx context.Context, actorID, operationKey, environmentID string, lifetime time.Duration) (EnrollmentGrant, error) {
	if s.store == nil || s.signer == nil || s.issuer == "" || s.encryptionKey == "" || actorID == "" || len(operationKey) < 8 || len(operationKey) > 128 || environmentID == "" || lifetime <= 0 || lifetime > 10*time.Minute {
		return EnrollmentGrant{}, ErrEnrollmentInvalid
	}
	environment, err := s.store.Queries().GetControlEnvironment(ctx, environmentID)
	if err != nil || !environment.OwnerUserID.Valid || environment.OwnerUserID.String != actorID || environment.DesiredState != "active" {
		return EnrollmentGrant{}, ErrEnrollmentInvalid
	}
	requestHash := enrollmentRequestHash(actorID, environmentID, lifetime)
	storedOperationKey := "helper-enrollment:" + actorID + ":" + operationKey
	if existing, err := s.store.Queries().GetControlHelperEnrollmentByOperationKey(ctx, storedOperationKey); err == nil {
		return s.replayGrant(existing, requestHash)
	} else if !errors.Is(err, sql.ErrNoRows) {
		return EnrollmentGrant{}, err
	}
	now := s.clock().UTC()
	helperID, enrollmentID, jti, err := randomEnrollmentValues()
	if err != nil {
		return EnrollmentGrant{}, err
	}
	expiresAt := now.Add(lifetime)
	credential, err := s.signer.SignCredential(mint.CredentialInput{Issuer: s.issuer, Audience: "paperboat-enrollment", Subject: environmentID, JTI: jti, IssuedAt: now, ExpiresAt: expiresAt, CredentialClass: "helper_enrollment", Scopes: []string{"helper:enroll"}, EnvironmentID: environmentID, EnrollmentID: enrollmentID})
	if err != nil {
		return EnrollmentGrant{}, err
	}
	jtiHash := sha256.Sum256([]byte(jti))
	grant := EnrollmentGrant{EnrollmentID: enrollmentID, HelperID: helperID, Credential: credential, ExpiresAt: expiresAt}
	grantJSON, err := json.Marshal(grant)
	if err != nil {
		return EnrollmentGrant{}, err
	}
	ciphertext, err := secrets.Encrypt(s.encryptionKey, string(grantJSON))
	if err != nil {
		return EnrollmentGrant{}, err
	}
	err = s.store.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		if _, err := tx.Queries().CreateControlHelper(ctx, dbsqlc.CreateControlHelperParams{ID: helperID, EnvironmentID: environmentID}); err != nil {
			return err
		}
		_, err := tx.Queries().CreateControlHelperEnrollment(ctx, dbsqlc.CreateControlHelperEnrollmentParams{ID: enrollmentID, EnvironmentID: environmentID, HelperID: helperID, JtiHash: jtiHash[:], OperationKey: storedOperationKey, RequestHash: requestHash[:], GrantCiphertext: ciphertext, ExpiresAt: expiresAt})
		if errors.Is(err, sql.ErrNoRows) {
			return errEnrollmentReplay
		}
		if err != nil {
			return err
		}
		if _, err := tx.Queries().BindControlConnectorHelper(ctx, dbsqlc.BindControlConnectorHelperParams{EnvironmentID: environmentID, HelperID: helperID, EdgePool: "default", UpdatedAt: now}); err != nil {
			return err
		}
		return s.audit.WriteTx(ctx, tx, audit.Event{ActorUserID: actorID, ActorType: audit.ActorUser, EventType: "helper.enrollment_issued", ResourceType: "helper", ResourceID: helperID, IdempotencyKey: "helper.enrollment_issued:" + enrollmentID, Metadata: map[string]any{"environment_id": environmentID, "expires_at": expiresAt}})
	})
	if errors.Is(err, errEnrollmentReplay) {
		existing, getErr := s.store.Queries().GetControlHelperEnrollmentByOperationKey(ctx, storedOperationKey)
		if getErr != nil {
			return EnrollmentGrant{}, getErr
		}
		return s.replayGrant(existing, requestHash)
	}
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.ConstraintName == "control_helper_enrollments_one_pending_per_environment" {
			pending, getErr := s.store.Queries().GetPendingControlHelperEnrollmentForEnvironment(ctx, environmentID)
			if getErr != nil {
				return EnrollmentGrant{}, getErr
			}
			return s.replayGrant(pending, requestHash)
		}
		return EnrollmentGrant{}, fmt.Errorf("persist enrollment: %w", err)
	}
	return grant, nil
}

var errEnrollmentReplay = errors.New("enrollment operation replay")

func enrollmentRequestHash(actorID, environmentID string, lifetime time.Duration) [32]byte {
	return sha256.Sum256([]byte(actorID + "\x00" + environmentID + "\x00" + lifetime.String()))
}

func (s *EnrollmentService) replayGrant(row dbsqlc.ControlHelperEnrollment, requestHash [32]byte) (EnrollmentGrant, error) {
	if !bytes.Equal(row.RequestHash, requestHash[:]) {
		return EnrollmentGrant{}, ErrUsageOperationConflict
	}
	plaintext, err := secrets.Decrypt(s.encryptionKey, row.GrantCiphertext)
	if err != nil {
		return EnrollmentGrant{}, ErrEnrollmentInvalid
	}
	var grant EnrollmentGrant
	if json.Unmarshal([]byte(plaintext), &grant) != nil {
		return EnrollmentGrant{}, ErrEnrollmentInvalid
	}
	return grant, nil
}

func (s *EnrollmentService) Exchange(ctx context.Context, credential string, publicKey []byte) (HelperIdentity, error) {
	now := s.clock().UTC()
	if s.store == nil || s.signer == nil || s.issuer == "" || len(publicKey) != ed25519.PublicKeySize {
		return HelperIdentity{}, ErrEnrollmentInvalid
	}
	thumbprintHash := sha256.Sum256(publicKey)
	keyThumbprint := "sha256:" + base64.RawURLEncoding.EncodeToString(thumbprintHash[:])
	claims, err := s.signer.VerifyCredential(credential, s.issuer, "helper_enrollment", now)
	if err != nil || claims.EnrollmentID == "" || claims.Subject != claims.EnvironmentID {
		return HelperIdentity{}, ErrEnrollmentInvalid
	}
	jtiHash := sha256.Sum256([]byte(claims.JTI))
	identityJTI, err := randomHex("jti_", 24)
	if err != nil {
		return HelperIdentity{}, err
	}
	expiresAt := now.Add(time.Hour)
	var result HelperIdentity
	err = s.store.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		enrollment, err := tx.Queries().ConsumeControlHelperEnrollment(ctx, dbsqlc.ConsumeControlHelperEnrollmentParams{ID: claims.EnrollmentID, JtiHash: jtiHash[:], Now: sql.NullTime{Time: now, Valid: true}})
		if errors.Is(err, sql.ErrNoRows) {
			return ErrEnrollmentUsed
		}
		if err != nil {
			return err
		}
		if enrollment.EnvironmentID != claims.EnvironmentID {
			return ErrEnrollmentInvalid
		}
		helper, err := tx.Queries().ActivateControlHelper(ctx, dbsqlc.ActivateControlHelperParams{ID: enrollment.HelperID, EnvironmentID: enrollment.EnvironmentID, KeyThumbprint: sql.NullString{String: keyThumbprint, Valid: true}, PublicKey: publicKey, Now: sql.NullTime{Time: now, Valid: true}})
		if errors.Is(err, sql.ErrNoRows) {
			return ErrEnrollmentUsed
		}
		if err != nil {
			return err
		}
		token, err := s.signer.SignCredential(mint.CredentialInput{Issuer: s.issuer, Audience: "paperboat-control", Subject: helper.ID, JTI: identityJTI, IssuedAt: now, ExpiresAt: expiresAt, CredentialClass: "helper_identity", Scopes: []string{"helper:connect", "helper:renew"}, EnvironmentID: helper.EnvironmentID, HelperID: helper.ID, KeyThumbprint: keyThumbprint})
		if err != nil {
			return err
		}
		if err := s.audit.WriteTx(ctx, tx, audit.Event{ActorType: audit.ActorSystem, EventType: "helper.enrollment_consumed", ResourceType: "helper", ResourceID: helper.ID, IdempotencyKey: "helper.enrollment_consumed:" + enrollment.ID, Metadata: map[string]any{"environment_id": helper.EnvironmentID}}); err != nil {
			return err
		}
		result = HelperIdentity{HelperID: helper.ID, EnvironmentID: helper.EnvironmentID, Credential: token, ExpiresAt: expiresAt}
		return nil
	})
	return result, err
}

func (s *EnrollmentService) Renew(ctx context.Context, identityToken string, proof, body []byte) (HelperIdentity, error) {
	claims, err := s.VerifyHelperRequest(ctx, identityToken, proof, "POST", "/v1/helpers/renew", body)
	if err != nil {
		return HelperIdentity{}, ErrHelperProof
	}
	var request struct {
		OperationID string `json:"operation_id"`
	}
	if json.Unmarshal(body, &request) != nil || request.OperationID != claims.OperationID {
		return HelperIdentity{}, ErrHelperProof
	}
	requestHash := sha256.Sum256(body)
	operationKey := "helper-renew:" + claims.HelperID + ":" + claims.OperationID
	if existing, err := s.store.Queries().GetHostedHelperIdentityRenewal(ctx, operationKey); err == nil {
		return s.replayIdentityRenewal(existing.RequestHash, existing.IdentityCiphertext, requestHash)
	} else if !errors.Is(err, sql.ErrNoRows) {
		return HelperIdentity{}, err
	}
	helper, err := s.store.Queries().GetActiveControlHelper(ctx, dbsqlc.GetActiveControlHelperParams{ID: claims.HelperID, EnvironmentID: claims.EnvironmentID})
	if err != nil || !helper.KeyThumbprint.Valid {
		return HelperIdentity{}, ErrHelperProof
	}
	now := s.clock().UTC()
	jti, err := randomHex("jti_", 24)
	if err != nil {
		return HelperIdentity{}, err
	}
	expiresAt := now.Add(time.Hour)
	token, err := s.signer.SignCredential(mint.CredentialInput{Issuer: s.issuer, Audience: "paperboat-control", Subject: helper.ID, JTI: jti, IssuedAt: now, ExpiresAt: expiresAt, CredentialClass: "helper_identity", Scopes: []string{"helper:connect", "helper:renew"}, EnvironmentID: helper.EnvironmentID, HelperID: helper.ID, KeyThumbprint: helper.KeyThumbprint.String})
	if err != nil {
		return HelperIdentity{}, err
	}
	result := HelperIdentity{HelperID: helper.ID, EnvironmentID: helper.EnvironmentID, Credential: token, ExpiresAt: expiresAt}
	encoded, err := json.Marshal(result)
	if err != nil {
		return HelperIdentity{}, err
	}
	ciphertext, err := secrets.Encrypt(s.encryptionKey, string(encoded))
	if err != nil {
		return HelperIdentity{}, err
	}
	_, err = s.store.Queries().CreateHostedHelperIdentityRenewal(ctx, dbsqlc.CreateHostedHelperIdentityRenewalParams{OperationKey: operationKey, HelperID: helper.ID, EnvironmentID: helper.EnvironmentID, RequestHash: requestHash[:], IdentityCiphertext: ciphertext, ExpiresAt: expiresAt})
	if errors.Is(err, sql.ErrNoRows) {
		existing, getErr := s.store.Queries().GetHostedHelperIdentityRenewal(ctx, operationKey)
		if getErr != nil {
			return HelperIdentity{}, getErr
		}
		return s.replayIdentityRenewal(existing.RequestHash, existing.IdentityCiphertext, requestHash)
	}
	return result, err
}

func (s *EnrollmentService) replayIdentityRenewal(storedHash, ciphertext []byte, requestHash [32]byte) (HelperIdentity, error) {
	if !bytes.Equal(storedHash, requestHash[:]) {
		return HelperIdentity{}, ErrUsageOperationConflict
	}
	plaintext, err := secrets.Decrypt(s.encryptionKey, ciphertext)
	if err != nil {
		return HelperIdentity{}, ErrEnrollmentInvalid
	}
	var result HelperIdentity
	if json.Unmarshal([]byte(plaintext), &result) != nil || result.HelperID == "" || result.EnvironmentID == "" || result.Credential == "" || result.ExpiresAt.IsZero() {
		return HelperIdentity{}, ErrEnrollmentInvalid
	}
	return result, nil
}

// ReplaceHelper fences the active helper and advances connector generation in
// one transaction. A subsequent enrollment binds the replacement helper to
// this already-advanced generation.
func (s *EnrollmentService) ReplaceHelper(ctx context.Context, actorID, operationKey, environmentID, helperID, edgePool string) (HelperReplacement, error) {
	if s.store == nil || actorID == "" || len(operationKey) < 8 || len(operationKey) > 128 || environmentID == "" || helperID == "" || edgePool == "" {
		return HelperReplacement{}, ErrEnrollmentInvalid
	}
	environment, err := s.store.Queries().GetControlEnvironment(ctx, environmentID)
	if err != nil || !environment.OwnerUserID.Valid || environment.OwnerUserID.String != actorID || environment.DesiredState != "active" {
		return HelperReplacement{}, ErrEnrollmentInvalid
	}
	now := s.clock().UTC()
	replacementOperationKey := "helper-replace:" + actorID + ":" + operationKey
	var result HelperReplacement
	err = s.store.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		current, err := tx.Queries().GetControlHelperForUpdate(ctx, dbsqlc.GetControlHelperForUpdateParams{ID: helperID, EnvironmentID: environmentID})
		if errors.Is(err, sql.ErrNoRows) {
			return ErrEnrollmentInvalid
		}
		if err != nil {
			return err
		}
		if current.State == "replaced" {
			if current.ReplacementOperationKey.Valid && current.ReplacementOperationKey.String == replacementOperationKey && current.ReplacementConnectorGeneration.Valid {
				result = HelperReplacement{EnvironmentID: environmentID, HelperID: helperID, ConnectorGeneration: current.ReplacementConnectorGeneration.Int64}
				return nil
			}
			return ErrUsageOperationConflict
		}
		if current.State != "active" {
			return ErrEnrollmentUsed
		}
		helper, err := tx.Queries().ReplaceControlHelper(ctx, dbsqlc.ReplaceControlHelperParams{ID: helperID, EnvironmentID: environmentID, OperationKey: sql.NullString{String: replacementOperationKey, Valid: true}, RevokedAt: sql.NullTime{Time: now, Valid: true}})
		if errors.Is(err, sql.ErrNoRows) {
			return ErrEnrollmentUsed
		}
		if err != nil {
			return err
		}
		if _, err := tx.Queries().RevokePendingHelperEnrollments(ctx, dbsqlc.RevokePendingHelperEnrollmentsParams{HelperID: helperID, RevokedAt: sql.NullTime{Time: now, Valid: true}}); err != nil {
			return err
		}
		generation, err := tx.Queries().AdvanceControlConnectorGeneration(ctx, dbsqlc.AdvanceControlConnectorGenerationParams{EnvironmentID: environmentID, HelperID: helperID, EdgePool: edgePool, UpdatedAt: now})
		if err != nil {
			return err
		}
		if _, err := tx.Queries().SetControlHelperReplacementGeneration(ctx, dbsqlc.SetControlHelperReplacementGenerationParams{ID: helperID, OperationKey: sql.NullString{String: replacementOperationKey, Valid: true}, ConnectorGeneration: sql.NullInt64{Int64: generation.Generation, Valid: true}, UpdatedAt: now}); err != nil {
			return err
		}
		if err := s.audit.WriteTx(ctx, tx, audit.Event{ActorUserID: actorID, ActorType: audit.ActorUser, EventType: "helper.replaced", ResourceType: "helper", ResourceID: helperID, IdempotencyKey: "helper.replaced:" + operationKey, Metadata: map[string]any{"environment_id": environmentID, "connector_generation": generation.Generation}}); err != nil {
			return err
		}
		result = HelperReplacement{EnvironmentID: environmentID, HelperID: helper.ID, ConnectorGeneration: generation.Generation}
		return nil
	})
	return result, err
}

func randomEnrollmentValues() (string, string, string, error) {
	helper, err := randomHex("hlp_", 12)
	if err != nil {
		return "", "", "", err
	}
	enrollment, err := randomHex("enr_", 12)
	if err != nil {
		return "", "", "", err
	}
	jti, err := randomHex("jti_", 24)
	return helper, enrollment, jti, err
}

func randomHex(prefix string, bytesCount int) (string, error) {
	value := make([]byte, bytesCount)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(value), nil
}
