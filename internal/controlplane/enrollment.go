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
	hostedApp     string
	hostedVerify  HostedWorkloadIdentityVerifier
}

type HostedWorkloadIdentity struct {
	AppName   string
	MachineID string
	TokenID   string
}

type HostedWorkloadIdentityVerifier interface {
	Verify(context.Context, string) (HostedWorkloadIdentity, error)
}

type HostedWorkloadIdentityVerifierFunc func(context.Context, string) (HostedWorkloadIdentity, error)

func (f HostedWorkloadIdentityVerifierFunc) Verify(ctx context.Context, token string) (HostedWorkloadIdentity, error) {
	return f(ctx, token)
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
	claims, err := s.VerifyHelperRequest(ctx, identityToken, proof, http.MethodPost, "/v1/environment-activity-observations", body)
	if err != nil || claims.EnvironmentID != environmentID {
		return ErrHelperProof
	}
	owned, err := s.store.Queries().HostedHelperOwnsMachine(ctx, dbsqlc.HostedHelperOwnsMachineParams{HelperID: claims.HelperID, EnvironmentID: environmentID, MachineID: machineID})
	if err == nil && !owned {
		owned, err = s.store.Queries().BYODHelperOwnsMachine(ctx, dbsqlc.BYODHelperOwnsMachineParams{HelperID: claims.HelperID, EnvironmentID: environmentID, MachineID: machineID})
	}
	if err != nil || !owned {
		return ErrHelperProof
	}
	return nil
}

func NewEnrollmentService(store *db.DB, signer *mint.Provider, writer *audit.Writer, issuer, encryptionKey string) *EnrollmentService {
	return &EnrollmentService{store: store, signer: signer, audit: writer, issuer: strings.TrimRight(strings.TrimSpace(issuer), "/"), encryptionKey: encryptionKey, clock: func() time.Time { return time.Now().UTC() }}
}

func (s *EnrollmentService) ConfigureHostedWorkloadIdentity(appName string, verifier HostedWorkloadIdentityVerifier) {
	s.hostedApp = strings.TrimSpace(appName)
	s.hostedVerify = verifier
}

func (s *EnrollmentService) ExchangeHostedWorkloadIdentity(ctx context.Context, token string, publicKey []byte) (HelperIdentity, error) {
	if s.hostedVerify == nil || s.hostedApp == "" || len(publicKey) != ed25519.PublicKeySize {
		return HelperIdentity{}, errors.Join(ErrEnrollmentInvalid, errEnrollmentInput)
	}
	identity, err := s.hostedVerify.Verify(ctx, token)
	if err != nil || identity.AppName != s.hostedApp || identity.MachineID == "" || identity.TokenID == "" {
		return HelperIdentity{}, errors.Join(ErrEnrollmentInvalid, errEnrollmentToken)
	}
	environment, err := s.store.Queries().GetHostedEnvironmentForMachine(ctx, identity.MachineID)
	if err != nil || !environment.OwnerUserID.Valid {
		return HelperIdentity{}, errors.Join(ErrEnrollmentInvalid, errEnrollmentToken)
	}
	tokenIDHash := sha256.Sum256([]byte(identity.TokenID))
	if helper, helperErr := s.store.Queries().GetActiveControlHelperForEnvironment(ctx, environment.ID); helperErr == nil {
		if !bytes.Equal(helper.PublicKey, publicKey) || !helper.KeyThumbprint.Valid {
			connector, connectorErr := s.store.Queries().GetControlConnectorGenerationForUpdate(ctx, environment.ID)
			if connectorErr != nil || connector.EdgePool == "" {
				return HelperIdentity{}, errors.Join(ErrEnrollmentInvalid, errEnrollmentConsume, connectorErr)
			}
			if _, replaceErr := s.ReplaceHelper(
				ctx, environment.OwnerUserID.String,
				"hosted-workload:"+hex.EncodeToString(tokenIDHash[:]),
				environment.ID, helper.ID, connector.EdgePool,
			); replaceErr != nil {
				return HelperIdentity{}, errors.Join(ErrEnrollmentInvalid, errEnrollmentConsume, replaceErr)
			}
		} else {
			result, issueErr := s.issueActiveHelperIdentity(helper)
			if issueErr != nil {
				return HelperIdentity{}, errors.Join(ErrEnrollmentInvalid, errEnrollmentConsume, issueErr)
			}
			if auditErr := s.audit.Write(ctx, audit.Event{
				ActorType: audit.ActorSystem, EventType: "helper.hosted_identity_recovered",
				ResourceType: "helper", ResourceID: helper.ID,
				IdempotencyKey: "helper.hosted_identity_recovered:" + hex.EncodeToString(tokenIDHash[:]),
				Metadata:       map[string]any{"environment_id": helper.EnvironmentID},
			}); auditErr != nil {
				return HelperIdentity{}, errors.Join(ErrEnrollmentInvalid, errEnrollmentPersist, auditErr)
			}
			return result, nil
		}
	} else if !errors.Is(helperErr, sql.ErrNoRows) {
		return HelperIdentity{}, errors.Join(ErrEnrollmentInvalid, errEnrollmentConsume, helperErr)
	}
	grant, err := s.EnsureBootGrant(
		ctx,
		environment.OwnerUserID.String,
		"hosted-workload:"+hex.EncodeToString(tokenIDHash[:8]),
		environment.ID,
		10*time.Minute,
	)
	if err != nil || grant.Credential == "" {
		return HelperIdentity{}, errors.Join(ErrEnrollmentInvalid, errEnrollmentConsume, err)
	}
	return s.Exchange(ctx, grant.Credential, publicKey)
}

func (s *EnrollmentService) issueActiveHelperIdentity(helper dbsqlc.ControlHelper) (HelperIdentity, error) {
	now := s.clock().UTC()
	jti, err := randomHex("jti_", 24)
	if err != nil {
		return HelperIdentity{}, err
	}
	expiresAt := now.Add(time.Hour)
	token, err := s.signer.SignCredential(mint.CredentialInput{
		Issuer: s.issuer, Audience: "paperboat-control", Subject: helper.ID, JTI: jti,
		IssuedAt: now, ExpiresAt: expiresAt, CredentialClass: "helper_identity",
		Scopes: []string{"helper:connect", "helper:renew"}, EnvironmentID: helper.EnvironmentID,
		HelperID: helper.ID, KeyThumbprint: helper.KeyThumbprint.String,
	})
	if err != nil {
		return HelperIdentity{}, err
	}
	return HelperIdentity{
		HelperID: helper.ID, EnvironmentID: helper.EnvironmentID,
		Credential: token, ExpiresAt: expiresAt,
	}, nil
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
	now := s.clock().UTC()
	if _, err := s.store.Queries().RevokeExpiredControlHelperEnrollments(ctx, dbsqlc.RevokeExpiredControlHelperEnrollmentsParams{Now: sql.NullTime{Time: now, Valid: true}, EnvironmentID: environmentID}); err != nil {
		return EnrollmentGrant{}, err
	}
	if existing, err := s.store.Queries().GetControlHelperEnrollmentByOperationKey(ctx, storedOperationKey); err == nil {
		return s.replayGrant(existing, requestHash)
	} else if !errors.Is(err, sql.ErrNoRows) {
		return EnrollmentGrant{}, err
	}
	helperID, enrollmentID, jti, err := randomEnrollmentValues()
	if err != nil {
		return EnrollmentGrant{}, err
	}
	reusePendingHelper := false
	if pending, pendingErr := s.store.Queries().GetPendingControlHelperForEnvironment(ctx, environmentID); pendingErr == nil {
		helperID, reusePendingHelper = pending.ID, true
	} else if !errors.Is(pendingErr, sql.ErrNoRows) {
		return EnrollmentGrant{}, pendingErr
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
		if !reusePendingHelper {
			if _, err := tx.Queries().CreateControlHelper(ctx, dbsqlc.CreateControlHelperParams{ID: helperID, EnvironmentID: environmentID}); err != nil {
				return err
			}
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

var (
	errEnrollmentInput    = errors.New("enrollment exchange input rejected")
	errEnrollmentToken    = errors.New("enrollment exchange token rejected")
	errEnrollmentConsume  = errors.New("enrollment exchange consumption failed")
	errEnrollmentActivate = errors.New("enrollment exchange activation failed")
	errEnrollmentPersist  = errors.New("enrollment exchange persistence failed")
)

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
		return HelperIdentity{}, errors.Join(ErrEnrollmentInvalid, errEnrollmentInput)
	}
	thumbprintHash := sha256.Sum256(publicKey)
	keyThumbprint := "sha256:" + base64.RawURLEncoding.EncodeToString(thumbprintHash[:])
	claims, err := s.signer.VerifyCredential(credential, s.issuer, "helper_enrollment", now)
	if err != nil || claims.EnrollmentID == "" || claims.Subject != claims.EnvironmentID {
		return HelperIdentity{}, errors.Join(ErrEnrollmentInvalid, errEnrollmentToken, err)
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
			return errors.Join(err, errEnrollmentConsume)
		}
		if enrollment.EnvironmentID != claims.EnvironmentID {
			return errors.Join(ErrEnrollmentInvalid, errEnrollmentConsume)
		}
		helper, err := tx.Queries().ActivateControlHelper(ctx, dbsqlc.ActivateControlHelperParams{ID: enrollment.HelperID, EnvironmentID: enrollment.EnvironmentID, KeyThumbprint: sql.NullString{String: keyThumbprint, Valid: true}, PublicKey: publicKey, Now: sql.NullTime{Time: now, Valid: true}})
		if errors.Is(err, sql.ErrNoRows) {
			return ErrEnrollmentUsed
		}
		if err != nil {
			return errors.Join(err, errEnrollmentActivate)
		}
		token, err := s.signer.SignCredential(mint.CredentialInput{Issuer: s.issuer, Audience: "paperboat-control", Subject: helper.ID, JTI: identityJTI, IssuedAt: now, ExpiresAt: expiresAt, CredentialClass: "helper_identity", Scopes: []string{"helper:connect", "helper:renew"}, EnvironmentID: helper.EnvironmentID, HelperID: helper.ID, KeyThumbprint: keyThumbprint})
		if err != nil {
			return err
		}
		if err := s.audit.WriteTx(ctx, tx, audit.Event{ActorType: audit.ActorSystem, EventType: "helper.enrollment_consumed", ResourceType: "helper", ResourceID: helper.ID, IdempotencyKey: "helper.enrollment_consumed:" + enrollment.ID, Metadata: map[string]any{"environment_id": helper.EnvironmentID}}); err != nil {
			return errors.Join(err, errEnrollmentPersist)
		}
		result = HelperIdentity{HelperID: helper.ID, EnvironmentID: helper.EnvironmentID, Credential: token, ExpiresAt: expiresAt}
		return nil
	})
	return result, err
}

// EnrollmentExchangeRejectionClass returns a bounded, non-secret operator diagnostic.
func EnrollmentExchangeRejectionClass(err error) string {
	switch {
	case errors.Is(err, ErrEnrollmentUsed):
		return "used"
	case errors.Is(err, errEnrollmentInput):
		return "input"
	case errors.Is(err, errEnrollmentToken):
		switch message := err.Error(); {
		case strings.Contains(message, "malformed"):
			return "token_malformed"
		case strings.Contains(message, "header"):
			return "token_header"
		case strings.Contains(message, "key is unknown"):
			return "token_key"
		case strings.Contains(message, "signature"):
			return "token_signature"
		case strings.Contains(message, "issuer"):
			return "token_issuer"
		case strings.Contains(message, "audience"):
			return "token_audience"
		case strings.Contains(message, "scopes"):
			return "token_scopes"
		case strings.Contains(message, "expired"):
			return "token_expired"
		case strings.Contains(message, "issued-at"):
			return "token_issued_at"
		case strings.Contains(message, "time window"):
			return "token_time_window"
		case strings.Contains(message, "ttl"):
			return "token_ttl"
		case strings.Contains(message, "class"):
			return "token_class"
		case strings.Contains(message, "base bindings"):
			return "token_base_binding"
		case strings.Contains(message, "claims"):
			return "token_claims"
		default:
			return "token_binding"
		}
	case errors.Is(err, errEnrollmentConsume):
		return "consume"
	case errors.Is(err, errEnrollmentActivate):
		return "activate"
	case errors.Is(err, errEnrollmentPersist):
		return "persistence"
	default:
		return "unknown"
	}
}

func (s *EnrollmentService) Renew(ctx context.Context, identityToken string, proof, body []byte) (HelperIdentity, error) {
	claims, err := s.VerifyHelperRequest(ctx, identityToken, proof, "POST", "/v1/helper-identity-renewals", body)
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
		if _, err := tx.Queries().RevokeControlConfigCredentialsForEnvironment(ctx, dbsqlc.RevokeControlConfigCredentialsForEnvironmentParams{EnvironmentID: environmentID, RevokedAt: sql.NullTime{Time: now, Valid: true}}); err != nil {
			return err
		}
		if _, err := tx.Queries().RevokeControlConfigRepositoryAccessForEnvironment(ctx, dbsqlc.RevokeControlConfigRepositoryAccessForEnvironmentParams{EnvironmentID: environmentID, Now: now}); err != nil {
			return err
		}
		if _, err := tx.Queries().RevokeControlConfigRepositoryLeasesForEnvironment(ctx, dbsqlc.RevokeControlConfigRepositoryLeasesForEnvironmentParams{EnvironmentID: sql.NullString{String: environmentID, Valid: true}, Now: sql.NullTime{Time: now, Valid: true}}); err != nil {
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
