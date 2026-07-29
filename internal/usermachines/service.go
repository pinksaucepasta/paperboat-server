package usermachines

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
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/pinksaucepasta/paperboat-server/internal/access"
	"github.com/pinksaucepasta/paperboat-server/internal/accessdescriptor"
	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
	"github.com/pinksaucepasta/paperboat-server/internal/helperruntime"
	"github.com/pinksaucepasta/paperboat-server/internal/mint"
	"github.com/pinksaucepasta/paperboat-server/internal/secrets"
)

var (
	ErrInvalidPairing             = errors.New("invalid user-machine pairing")
	ErrPairingExpired             = errors.New("user-machine pairing expired")
	ErrPairingUsed                = errors.New("user-machine pairing is no longer pending")
	ErrSeatUnavailable            = errors.New("user-machine seat unavailable")
	ErrNotFound                   = errors.New("user machine not found")
	ErrBandwidthDenied            = errors.New("user-machine bandwidth is unavailable")
	ErrInvalidBandwidth           = errors.New("user-machine bandwidth request is invalid")
	ErrInstallationPending        = errors.New("user-machine installation approval is pending")
	ErrInstallationDenied         = errors.New("user-machine installation was denied")
	ErrInstallationExpired        = errors.New("user-machine installation pairing expired")
	ErrInstallationUnavailable    = errors.New("user-machine installation material is unavailable")
	ErrProvisioningUnavailable    = errors.New("user-machine canonical helper provisioning is unavailable")
	ErrEnrollmentNotFound         = errors.New("user-machine enrollment not found")
	ErrEnrollmentState            = errors.New("user-machine enrollment state does not allow this operation")
	ErrIdempotencyKeyRequired     = errors.New("user-machine enrollment idempotency key is required")
	ErrTerminalSessionNotFound    = errors.New("user-machine terminal session not found")
	ErrTerminalSessionReserved    = errors.New("user-machine default terminal session is reserved")
	ErrTerminalSessionLimit       = errors.New("user-machine terminal session limit reached")
	ErrTerminalSessionConflict    = errors.New("user-machine terminal session name conflict")
	ErrTerminalSessionInvalidName = errors.New("invalid user-machine terminal session name")
	ErrTerminalSessionIdempotency = errors.New("terminal session idempotency key is required")
	ErrTerminalSessionInvalidMode = errors.New("invalid user-machine terminal session mode")
)

var (
	terminalSessionNamePattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	automaticTerminalNamePattern = regexp.MustCompile(`^shell-[0-9]+$`)
)

type SeatAuthorizer interface {
	ReserveUserMachineSeat(context.Context, *db.Tx, string) error
}

func (s *Service) ConsumeInstallation(ctx context.Context, verifier string) (json.RawMessage, error) {
	if strings.TrimSpace(verifier) == "" || strings.TrimSpace(s.encryptionKey) == "" {
		return nil, ErrInstallationUnavailable
	}
	hash := sha256.Sum256([]byte(verifier))
	var ciphertext []byte
	err := s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		value, err := tx.Queries().ConsumeUserMachineInstallationConfig(ctx, hash[:])
		if errors.Is(err, sql.ErrNoRows) {
			pairing, lookupErr := tx.Queries().GetUserMachinePairingForVerifier(ctx, hash[:])
			if errors.Is(lookupErr, sql.ErrNoRows) {
				return ErrInstallationUnavailable
			}
			if lookupErr != nil {
				return lookupErr
			}
			if pairing.State == "denied" {
				return ErrInstallationDenied
			}
			if pairing.State == "expired" || !time.Now().UTC().Before(pairing.ExpiresAt) {
				return ErrInstallationExpired
			}
			if pairing.State == "pending" {
				return ErrInstallationPending
			}
			return ErrInstallationUnavailable
		}
		if err != nil {
			return err
		}
		ciphertext = value
		return nil
	})
	if err != nil {
		return nil, err
	}
	plaintext, err := secrets.Decrypt(s.encryptionKey, ciphertext)
	if err != nil || !json.Valid([]byte(plaintext)) {
		return nil, ErrInstallationUnavailable
	}
	return json.RawMessage(plaintext), nil
}

type Policy struct {
	PairingLifetime  time.Duration
	OfflineAfter     time.Duration
	AllowedPlatforms []string
}
type Service struct {
	db                 *db.DB
	audit              *audit.Writer
	policy             Policy
	seats              SeatAuthorizer
	now                func() time.Time
	provisioner        access.Client
	encryptionKey      string
	credentials        access.CredentialIssuer
	issuer             string
	ttl                time.Duration
	fileTransferPolicy accessdescriptor.FileTransferPolicy
	maxSessions        int
	controlSigner      *mint.Provider
	controlRuntime     userMachineHelperRuntime
	bootstrapCommand   string
	helperGrant        func(context.Context, string, string, string, time.Duration) (HelperEnrollmentGrant, error)
	helperArtifacts    map[string]HelperArtifact
	artifactPublicKey  string
	helperBaseDomain   string
	helperListenPort   int32
}

type userMachineHelperRuntime interface {
	Terminal(context.Context, string, string, string, string, string) (helperruntime.Snapshot, error)
}

type HelperEnrollmentGrant struct {
	EnrollmentID string    `json:"enrollment_id"`
	HelperID     string    `json:"helper_id"`
	Credential   string    `json:"credential"`
	ExpiresAt    time.Time `json:"expires_at"`
}

func (s *Service) FailInstallation(ctx context.Context, enrollmentID, environmentID, helperID, helperEnrollmentID, stage string) error {
	if strings.TrimSpace(enrollmentID) == "" || strings.TrimSpace(environmentID) == "" || strings.TrimSpace(helperID) == "" || strings.TrimSpace(helperEnrollmentID) == "" || !slices.Contains([]string{"artifact_verification", "service_install", "service_readiness"}, stage) {
		return ErrEnrollmentState
	}
	return s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		result, err := tx.Queries().FailUserMachineEnrollmentForHelper(ctx, dbsqlc.FailUserMachineEnrollmentForHelperParams{ID: enrollmentID, EnvironmentID: environmentID, HelperID: helperID, HelperEnrollmentID: helperEnrollmentID})
		if err != nil {
			return err
		}
		if result.FailedCount != 1 || result.ReleasedCount != 1 || result.RevokedHelperCount != 1 || result.RevokedGrantCount < 1 {
			return ErrEnrollmentState
		}
		return s.audit.WriteTx(ctx, tx, audit.Event{ActorType: audit.ActorSystem, EventType: "user_machine.installation_failed", ResourceType: "user_machine_enrollment", ResourceID: enrollmentID, IdempotencyKey: "user_machine.installation_failed:" + enrollmentID + ":" + stage, Metadata: map[string]any{"environment_id": environmentID, "helper_id": helperID, "stage": stage}})
	})
}

type HelperArtifact struct {
	Schema       string `json:"schema"`
	Kind         string `json:"kind"`
	Version      string `json:"version"`
	Platform     string `json:"platform"`
	Architecture string `json:"architecture"`
	URL          string `json:"url"`
	ByteLength   int64  `json:"byte_length"`
	SHA256       string `json:"sha256"`
	Signature    string `json:"signature"`
}

// Worker retries revocations after the connector becomes reachable again. A
// machine may be offline when a user disconnects it, so revocation must not
// depend on a synchronous Helper response.
func (s *Service) Worker(interval time.Duration) func(context.Context) error {
	if interval <= 0 {
		interval = time.Second
	}
	return func(ctx context.Context) error {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			_ = s.RetryPendingRevocations(ctx)
			_ = s.processDueTerminalSessionOperations(ctx)
			_, _ = s.db.Queries().MarkStaleUserMachinesOffline(ctx, sql.NullTime{Time: s.now().UTC().Add(-s.policy.OfflineAfter), Valid: true})
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-ticker.C:
			}
		}
	}
}

func (s *Service) ConfigureProvisioning(provider access.Client, encryptionKey string) {
	s.provisioner, s.encryptionKey = provider, encryptionKey
}

func (s *Service) ConfigureAccess(credentials access.CredentialIssuer, issuer string, ttl time.Duration) {
	s.credentials, s.issuer, s.ttl = credentials, strings.TrimRight(issuer, "/"), ttl
}

func (s *Service) ConfigureFileTransfer(policy accessdescriptor.FileTransferPolicy) {
	s.fileTransferPolicy = policy
}

func (s *Service) ConfigureTerminalSessions(maxActive int, signer *mint.Provider, client *http.Client) {
	if maxActive > 0 {
		s.maxSessions = min(maxActive, 20)
	}
	s.controlSigner = signer
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	s.controlRuntime = helperruntime.Client{HTTPClient: client}
}

func (s *Service) ConfigureBootstrapCommand(command string) {
	s.bootstrapCommand = strings.TrimSpace(command)
}

func (s *Service) ConfigureHelperRoute(baseDomain string, listenPort int32) error {
	baseDomain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(baseDomain), "."))
	if baseDomain == "" || listenPort < 1024 || listenPort > 65535 {
		return errors.New("user-machine helper route configuration is invalid")
	}
	s.helperBaseDomain, s.helperListenPort = baseDomain, listenPort
	return nil
}

func (s *Service) ConfigureHelperEnrollment(issuer func(context.Context, string, string, string, time.Duration) (HelperEnrollmentGrant, error)) {
	s.helperGrant = issuer
}

func (s *Service) ConfigureHelperArtifacts(encoded, publicKey string) error {
	if strings.TrimSpace(encoded) == "" && strings.TrimSpace(publicKey) == "" {
		return nil
	}
	var artifacts []HelperArtifact
	decoder := json.NewDecoder(strings.NewReader(encoded))
	decoder.DisallowUnknownFields()
	decodedPublicKey, keyErr := decodeArtifactBase64(strings.TrimSpace(publicKey))
	if err := decoder.Decode(&artifacts); err != nil || len(artifacts) < 2 || len(artifacts) > 8 || len(artifacts)%2 != 0 || keyErr != nil || len(decodedPublicKey) != ed25519.PublicKeySize {
		return errors.New("user-machine helper artifacts are invalid")
	}
	configured := make(map[string]HelperArtifact, len(artifacts))
	for _, artifact := range artifacts {
		key := artifact.Platform + "-" + artifact.Architecture + "-" + artifact.Kind
		parsedURL, urlErr := url.Parse(artifact.URL)
		digest, digestErr := hex.DecodeString(artifact.SHA256)
		signature, signatureErr := decodeArtifactBase64(artifact.Signature)
		payload, payloadErr := json.Marshal(struct {
			Architecture string `json:"architecture"`
			ByteLength   int64  `json:"byte_length"`
			Kind         string `json:"kind"`
			Platform     string `json:"platform"`
			Schema       string `json:"schema"`
			SHA256       string `json:"sha256"`
			URL          string `json:"url"`
			Version      string `json:"version"`
		}{artifact.Architecture, artifact.ByteLength, artifact.Kind, artifact.Platform, artifact.Schema, artifact.SHA256, artifact.URL, artifact.Version})
		if artifact.Schema != "paperboat.helper-artifact/v2" || !slices.Contains([]string{"worker", "host_service"}, artifact.Kind) || artifact.Version == "" || !slices.Contains([]string{"darwin", "linux"}, artifact.Platform) || !slices.Contains([]string{"amd64", "arm64"}, artifact.Architecture) || urlErr != nil || parsedURL.Scheme != "https" || parsedURL.User != nil || parsedURL.Hostname() == "" || parsedURL.RawQuery != "" || parsedURL.Fragment != "" || artifact.ByteLength < 1 || artifact.ByteLength > 256<<20 || digestErr != nil || len(digest) != sha256.Size || signatureErr != nil || len(signature) != ed25519.SignatureSize || payloadErr != nil || !ed25519.Verify(ed25519.PublicKey(decodedPublicKey), payload, signature) || configured[key].Schema != "" {
			return errors.New("user-machine helper artifacts are invalid")
		}
		configured[key] = artifact
	}
	for _, artifact := range configured {
		counterpartKind := "worker"
		if artifact.Kind == "worker" {
			counterpartKind = "host_service"
		}
		counterpart, ok := configured[artifact.Platform+"-"+artifact.Architecture+"-"+counterpartKind]
		if !ok || counterpart.Version != artifact.Version {
			return errors.New("user-machine helper artifacts are invalid")
		}
	}
	if len(configured) != len(artifacts) {
		return errors.New("user-machine helper artifacts are invalid")
	}
	s.helperArtifacts, s.artifactPublicKey = configured, strings.TrimSpace(publicKey)
	return nil
}

func decodeArtifactBase64(value string) ([]byte, error) {
	if decoded, err := base64.RawURLEncoding.DecodeString(value); err == nil {
		return decoded, nil
	}
	return base64.StdEncoding.DecodeString(value)
}

func New(store *db.DB, auditWriter *audit.Writer, policy Policy, seats SeatAuthorizer) *Service {
	if policy.OfflineAfter <= 0 {
		policy.OfflineAfter = 2 * time.Minute
	}
	return &Service{db: store, audit: auditWriter, policy: policy, seats: seats, now: time.Now, maxSessions: 20}
}

type PairingInput struct {
	Verifier, EnrollmentToken, DisplayName, Platform, Architecture, WorkspaceRoot string
	RuntimeVersions                                                               json.RawMessage
}

type Enrollment struct {
	ID                   string     `json:"id"`
	OperationID          string     `json:"operation_id"`
	State                string     `json:"state"`
	Generation           int64      `json:"generation"`
	PairingID            string     `json:"pairing_id,omitempty"`
	UserCode             string     `json:"user_code,omitempty"`
	UserMachineID        string     `json:"user_machine_id,omitempty"`
	RequestedDisplayName string     `json:"requested_display_name,omitempty"`
	Platform             string     `json:"platform,omitempty"`
	Architecture         string     `json:"architecture,omitempty"`
	WorkspaceRoot        string     `json:"workspace_root,omitempty"`
	ExpiresAt            time.Time  `json:"expires_at"`
	CancelledAt          *time.Time `json:"cancelled_at,omitempty"`
	CreatedAt            time.Time  `json:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at"`
}

type EnrollmentStart struct {
	Enrollment
	BootstrapToken   string `json:"bootstrap_token"`
	BootstrapCommand string `json:"bootstrap_command"`
}

func (s *Service) StartEnrollment(ctx context.Context, userID, idempotencyKey string) (EnrollmentStart, error) {
	userID, idempotencyKey = strings.TrimSpace(userID), strings.TrimSpace(idempotencyKey)
	if userID == "" || idempotencyKey == "" || len(idempotencyKey) > 128 {
		return EnrollmentStart{}, ErrIdempotencyKeyRequired
	}
	if strings.TrimSpace(s.encryptionKey) == "" {
		return EnrollmentStart{}, errors.New("user-machine enrollment encryption is not configured")
	}
	token, err := randomCode(48)
	if err != nil {
		return EnrollmentStart{}, err
	}
	hash := sha256.Sum256([]byte(token))
	ciphertext, err := secrets.Encrypt(s.encryptionKey, token)
	if err != nil {
		return EnrollmentStart{}, err
	}
	expires := s.now().UTC().Add(s.policy.PairingLifetime)
	row, err := s.db.Queries().CreateUserMachineEnrollment(ctx, dbsqlc.CreateUserMachineEnrollmentParams{
		ID: newID("ume"), UserID: userID, OperationID: newID("op_enroll"), IdempotencyKey: idempotencyKey,
		BootstrapTokenHash: hash[:], BootstrapTokenCiphertext: ciphertext, ExpiresAt: expires,
	})
	if err != nil {
		return EnrollmentStart{}, err
	}
	if !bytes.Equal(row.BootstrapTokenHash, hash[:]) {
		token, err = secrets.Decrypt(s.encryptionKey, row.BootstrapTokenCiphertext)
		if err != nil {
			return EnrollmentStart{}, err
		}
	}
	result := EnrollmentStart{Enrollment: mapEnrollment(row), BootstrapToken: token, BootstrapCommand: s.enrollmentCommand(token)}
	_ = s.audit.Write(ctx, audit.Event{ActorUserID: userID, ActorType: audit.ActorUser, EventType: "user_machine.enrollment_started", ResourceType: "user_machine_enrollment", ResourceID: row.ID, IdempotencyKey: "user_machine.enrollment_started:" + row.ID, Metadata: map[string]any{"operation_id": row.OperationID, "generation": row.Generation}})
	return result, nil
}

func (s *Service) Enrollment(ctx context.Context, userID, enrollmentID string) (Enrollment, error) {
	_, _ = s.db.Queries().ExpireUserMachineEnrollment(ctx, dbsqlc.ExpireUserMachineEnrollmentParams{ID: strings.TrimSpace(enrollmentID), UserID: strings.TrimSpace(userID)})
	row, err := s.db.Queries().GetUserMachineEnrollmentForUser(ctx, dbsqlc.GetUserMachineEnrollmentForUserParams{ID: strings.TrimSpace(enrollmentID), UserID: strings.TrimSpace(userID)})
	if errors.Is(err, sql.ErrNoRows) {
		return Enrollment{}, ErrEnrollmentNotFound
	}
	if err != nil {
		return Enrollment{}, err
	}
	result := mapEnrollment(row)
	if row.PairingID.Valid {
		pairing, pairingErr := s.db.Queries().GetUserMachinePairingByID(ctx, row.PairingID.String)
		if pairingErr == nil {
			result.UserCode = pairing.UserCode
		}
		if pairingErr != nil && !errors.Is(pairingErr, sql.ErrNoRows) {
			return Enrollment{}, pairingErr
		}
	}
	return result, nil
}

func (s *Service) CancelEnrollment(ctx context.Context, userID, enrollmentID string) error {
	n, err := s.db.Queries().CancelUserMachineEnrollment(ctx, dbsqlc.CancelUserMachineEnrollmentParams{ID: strings.TrimSpace(enrollmentID), UserID: strings.TrimSpace(userID)})
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrEnrollmentState
	}
	return s.audit.Write(ctx, audit.Event{ActorUserID: userID, ActorType: audit.ActorUser, EventType: "user_machine.enrollment_cancelled", ResourceType: "user_machine_enrollment", ResourceID: enrollmentID, IdempotencyKey: "user_machine.enrollment_cancelled:" + enrollmentID})
}

func (s *Service) RetryEnrollment(ctx context.Context, userID, enrollmentID string) (EnrollmentStart, error) {
	if strings.TrimSpace(s.encryptionKey) == "" {
		return EnrollmentStart{}, errors.New("user-machine enrollment encryption is not configured")
	}
	token, err := randomCode(48)
	if err != nil {
		return EnrollmentStart{}, err
	}
	hash := sha256.Sum256([]byte(token))
	ciphertext, err := secrets.Encrypt(s.encryptionKey, token)
	if err != nil {
		return EnrollmentStart{}, err
	}
	row, err := s.db.Queries().RetryUserMachineEnrollment(ctx, dbsqlc.RetryUserMachineEnrollmentParams{BootstrapTokenHash: hash[:], BootstrapTokenCiphertext: ciphertext, ExpiresAt: s.now().UTC().Add(s.policy.PairingLifetime), ID: strings.TrimSpace(enrollmentID), UserID: strings.TrimSpace(userID)})
	if errors.Is(err, sql.ErrNoRows) {
		return EnrollmentStart{}, ErrEnrollmentState
	}
	if err != nil {
		return EnrollmentStart{}, err
	}
	return EnrollmentStart{Enrollment: mapEnrollment(row), BootstrapToken: token, BootstrapCommand: s.enrollmentCommand(token)}, nil
}

func (s *Service) enrollmentCommand(token string) string {
	command := strings.TrimSpace(s.bootstrapCommand)
	if command == "" {
		return ""
	}
	return command + " --enrollment-token " + token
}

func mapEnrollment(row dbsqlc.UserMachineEnrollment) Enrollment {
	result := Enrollment{ID: row.ID, OperationID: row.OperationID, State: row.State, Generation: row.Generation, PairingID: row.PairingID.String, UserMachineID: row.UserMachineID.String, RequestedDisplayName: row.RequestedDisplayName.String, Platform: row.Platform.String, Architecture: row.Architecture.String, WorkspaceRoot: row.WorkspaceRoot.String, ExpiresAt: row.ExpiresAt, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt}
	if row.CancelledAt.Valid {
		value := row.CancelledAt.Time
		result.CancelledAt = &value
	}
	return result
}

type Pairing struct {
	ID        string    `json:"id"`
	UserCode  string    `json:"user_code"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (s *Service) CreatePairing(ctx context.Context, in PairingInput) (Pairing, error) {
	if err := s.validatePairing(in); err != nil {
		return Pairing{}, err
	}
	verifierHash := sha256.Sum256([]byte(in.Verifier))
	code, err := randomCode(8)
	if err != nil {
		return Pairing{}, err
	}
	if len(in.RuntimeVersions) == 0 {
		in.RuntimeVersions = json.RawMessage(`{}`)
	}
	expires := s.now().UTC().Add(s.policy.PairingLifetime)
	params := dbsqlc.CreateUserMachinePairingParams{ID: newID("ump"), VerifierHash: verifierHash[:], UserCode: code, RequestedDisplayName: strings.TrimSpace(in.DisplayName), Platform: strings.ToLower(strings.TrimSpace(in.Platform)), Architecture: strings.ToLower(strings.TrimSpace(in.Architecture)), WorkspaceRoot: filepath.Clean(in.WorkspaceRoot), RuntimeVersions: in.RuntimeVersions, ExpiresAt: expires}
	var row dbsqlc.UserMachinePairing
	if strings.TrimSpace(in.EnrollmentToken) == "" {
		row, err = s.db.Queries().CreateUserMachinePairing(ctx, params)
	} else {
		tokenHash := sha256.Sum256([]byte(strings.TrimSpace(in.EnrollmentToken)))
		err = s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
			enrollment, err := tx.Queries().GetUserMachineEnrollmentForTokenUpdate(ctx, tokenHash[:])
			if errors.Is(err, sql.ErrNoRows) {
				return ErrEnrollmentNotFound
			}
			if err != nil {
				return err
			}
			if enrollment.State != "awaiting_bootstrap" || !s.now().UTC().Before(enrollment.ExpiresAt) {
				return ErrEnrollmentState
			}
			if enrollment.ExpiresAt.Before(params.ExpiresAt) {
				params.ExpiresAt = enrollment.ExpiresAt
			}
			row, err = tx.Queries().CreateUserMachinePairing(ctx, params)
			if err != nil {
				return err
			}
			n, err := tx.Queries().ClaimUserMachineEnrollment(ctx, dbsqlc.ClaimUserMachineEnrollmentParams{PairingID: sql.NullString{String: row.ID, Valid: true}, RequestedDisplayName: sql.NullString{String: params.RequestedDisplayName, Valid: true}, Platform: sql.NullString{String: params.Platform, Valid: true}, Architecture: sql.NullString{String: params.Architecture, Valid: true}, WorkspaceRoot: sql.NullString{String: params.WorkspaceRoot, Valid: true}, ID: enrollment.ID})
			if err != nil {
				return err
			}
			if n != 1 {
				return ErrEnrollmentState
			}
			return nil
		})
	}
	if err != nil {
		return Pairing{}, err
	}
	return Pairing{ID: row.ID, UserCode: row.UserCode, ExpiresAt: row.ExpiresAt}, nil
}

type UserMachine struct {
	ID                 string             `json:"id"`
	EnvironmentID      string             `json:"environment_id"`
	DisplayName        string             `json:"display_name"`
	Platform           string             `json:"platform"`
	Architecture       string             `json:"architecture"`
	WorkspaceRoot      string             `json:"workspace_root"`
	State              string             `json:"state"`
	SeatState          string             `json:"seat_state"`
	Online             bool               `json:"online"`
	RuntimeVersions    json.RawMessage    `json:"runtime_versions"`
	EnrolledAt         *time.Time         `json:"enrolled_at,omitempty"`
	LastSeenAt         *time.Time         `json:"last_seen_at,omitempty"`
	Availability       AvailabilityPolicy `json:"availability"`
	RuntimeDiagnostics RuntimeDiagnostics `json:"runtime_diagnostics"`
}

type RuntimeDiagnostics struct {
	WorkerGeneration    uint64     `json:"worker_generation"`
	OSBootID            string     `json:"os_boot_id,omitempty"`
	WorkerServiceScope  string     `json:"worker_service_scope"`
	ConnectorState      string     `json:"connector_state"`
	ConnectorGeneration uint64     `json:"connector_generation"`
	ObservedAt          *time.Time `json:"observed_at,omitempty"`
}

// Overview is the dashboard-safe accounting snapshot. Bytes are returned as
// integers so every client can choose its own display units without affecting
// the authoritative accounting values.
type Overview struct {
	EntitlementState string    `json:"entitlement_state"`
	ProductCode      string    `json:"product_code,omitempty"`
	PeriodStart      time.Time `json:"period_start,omitempty"`
	PeriodEnd        time.Time `json:"period_end,omitempty"`
	SeatQuantity     int32     `json:"seat_quantity"`
	OccupiedSeats    int32     `json:"occupied_seats"`
	AvailableSeats   int32     `json:"available_seats"`
	IncludedBytes    int64     `json:"included_bytes"`
	ConsumedIncluded int64     `json:"consumed_included_bytes"`
	ConsumedTopup    int64     `json:"consumed_topup_bytes"`
	TopupRemaining   int64     `json:"paid_topup_remaining_bytes"`
	BootstrapCommand string    `json:"bootstrap_command,omitempty"`
}

func (s *Service) Overview(ctx context.Context, userID string) (Overview, error) {
	entitlement, err := s.db.Queries().GetUserMachineEntitlement(ctx, userID)
	if errors.Is(err, sql.ErrNoRows) {
		return Overview{EntitlementState: "unavailable"}, nil
	}
	if err != nil {
		return Overview{}, err
	}
	occupied, err := s.db.Queries().CountOccupiedUserMachineSeats(ctx, userID)
	if err != nil {
		return Overview{}, err
	}
	usage, err := s.db.Queries().GetUserMachineBandwidthUsage(ctx, userID)
	if err != nil {
		return Overview{}, err
	}
	available := entitlement.SeatQuantity - occupied
	entitlementState := entitlement.State
	if !entitlementActive(entitlement.State, entitlement.CurrentPeriodEnd, s.now().UTC()) {
		available = 0
		entitlementState = "expired"
	}
	if available < 0 {
		available = 0
	}
	return Overview{
		EntitlementState: entitlementState, ProductCode: entitlement.ProductCode,
		PeriodStart: entitlement.CurrentPeriodStart, PeriodEnd: entitlement.CurrentPeriodEnd,
		SeatQuantity: entitlement.SeatQuantity, OccupiedSeats: occupied, AvailableSeats: available,
		IncludedBytes: usage.IncludedBytes, ConsumedIncluded: usage.ConsumedIncludedBytes,
		ConsumedTopup: usage.ConsumedTopupBytes, TopupRemaining: usage.PaidTopupRemainingBytes,
		BootstrapCommand: s.bootstrapCommand,
	}, nil
}

func entitlementActive(state string, periodEnd, now time.Time) bool {
	return (state == "active" || state == "trialing") && now.Before(periodEnd)
}

type TerminalSession struct {
	ID             string           `json:"id"`
	Name           string           `json:"name"`
	IsDefault      bool             `json:"is_default"`
	State          string           `json:"state"`
	AttachedCount  *int             `json:"attached_count,omitempty"`
	LastActiveAt   *time.Time       `json:"last_active_at,omitempty"`
	CreatedAt      time.Time        `json:"created_at"`
	UpdatedAt      time.Time        `json:"updated_at"`
	TerminalMode   string           `json:"terminal_mode"`
	EvictedSession *TerminalSession `json:"evicted_session,omitempty"`
}

// BandwidthReservation is a trusted capacity grant. A data-plane relay must
// forward no more than GrantedBytes before requesting another grant.
type BandwidthReservation struct {
	GrantedBytes int64 `json:"granted_bytes"`
	Exhausted    bool  `json:"exhausted"`
}

type ConnectionDescriptor struct {
	Schema            string         `json:"schema,omitempty"`
	Capabilities      []string       `json:"capabilities,omitempty"`
	Issuer            string         `json:"issuer,omitempty"`
	UserMachineID     string         `json:"user_machine_id"`
	UserMachineState  string         `json:"user_machine_state"`
	Connectable       bool           `json:"connectable"`
	ExpiresAt         time.Time      `json:"expires_at"`
	Environment       map[string]any `json:"environment,omitempty"`
	Terminal          map[string]any `json:"terminal,omitempty"`
	FileTransfer      map[string]any `json:"file_transfer,omitempty"`
	Status            string         `json:"status,omitempty"`
	Reason            string         `json:"reason,omitempty"`
	RetryAfterSeconds int            `json:"retry_after_seconds,omitempty"`
}

func (r ConnectionDescriptor) MarshalJSON() ([]byte, error) {
	if r.Schema != accessdescriptor.SchemaV1 {
		return nil, errors.New("connection descriptor schema is required")
	}
	environment, ok := r.Environment["id"].(string)
	if !ok || environment == "" {
		return nil, errors.New("canonical environment descriptor is incomplete")
	}
	env := accessdescriptor.Environment{
		ID: environment, Kind: stringValue(r.Environment, "kind"), ResourceID: stringValue(r.Environment, "resource_id"),
		DisplayName: stringValue(r.Environment, "display_name"), State: stringValue(r.Environment, "state"), Root: stringValue(r.Environment, "root"),
	}
	if env.Kind == "" || env.ResourceID == "" || env.DisplayName == "" || env.State == "" {
		return nil, errors.New("canonical environment descriptor is incomplete")
	}
	out := accessdescriptor.Descriptor{Schema: r.Schema, Issuer: r.Issuer, Connectable: r.Connectable, ExpiresAt: r.ExpiresAt, Environment: env, Capabilities: slices.Clone(r.Capabilities), Status: r.Status, Reason: r.Reason, RetryAfterSeconds: r.RetryAfterSeconds}
	if r.Terminal != nil && r.Terminal["auth"] != nil {
		terminal, err := decodeCanonical[accessdescriptor.Terminal](r.Terminal)
		if err != nil {
			return nil, err
		}
		out.Terminal = &terminal
	}
	if r.FileTransfer != nil && r.FileTransfer["auth"] != nil {
		transfer, err := decodeCanonical[accessdescriptor.FileTransfer](r.FileTransfer)
		if err != nil {
			return nil, err
		}
		out.FileTransfer = &transfer
	}
	return json.Marshal(out)
}

func stringValue(value map[string]any, key string) string {
	result, _ := value[key].(string)
	return result
}

func decodeCanonical[T any](value any) (T, error) {
	var out T
	b, err := json.Marshal(value)
	if err != nil {
		return out, err
	}
	err = json.Unmarshal(b, &out)
	return out, err
}

func machineConnectionState(connectable bool, state string) string {
	if connectable {
		return "ready"
	}
	switch state {
	case "deleted":
		return "deleted"
	case "revoked", "disconnected":
		return "revoked"
	case "starting", "provisioning":
		return "starting"
	default:
		return "offline"
	}
}

func setCanonicalMachineIdentity(response *ConnectionDescriptor, row dbsqlc.UserMachine) {
	response.Schema = accessdescriptor.SchemaV1
	response.Capabilities = []string{accessdescriptor.CapabilityTerminal, accessdescriptor.CapabilityHerdr, accessdescriptor.CapabilityFileTransfer, accessdescriptor.CapabilityPreview}
	response.Environment = map[string]any{"id": row.EnvironmentID, "kind": accessdescriptor.EnvironmentBYOD, "resource_id": row.ID, "display_name": row.DisplayName, "state": machineConnectionState(response.Connectable, row.State), "root": row.WorkspaceRoot}
}

func (s *Service) Connect(ctx context.Context, userID, userMachineID, cliClientSessionID string) (ConnectionDescriptor, error) {
	return s.ConnectTerminalSession(ctx, userID, userMachineID, cliClientSessionID, "")
}

func (s *Service) ConnectTerminalSession(ctx context.Context, userID, userMachineID, cliClientSessionID, terminalSessionID string) (ConnectionDescriptor, error) {
	row, err := s.db.Queries().GetUserMachineForUser(ctx, dbsqlc.GetUserMachineForUserParams{ID: userMachineID, UserID: userID})
	if errors.Is(err, sql.ErrNoRows) {
		return ConnectionDescriptor{}, ErrNotFound
	}
	if err != nil {
		return ConnectionDescriptor{}, err
	}
	terminalSession, err := s.terminalSession(ctx, userID, userMachineID, terminalSessionID)
	if err != nil {
		return ConnectionDescriptor{}, err
	}
	ttl := s.ttl
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	if s.controlSigner != nil && ttl > 5*time.Minute {
		ttl = 5 * time.Minute
	}
	expires := s.now().UTC().Add(ttl)
	response := ConnectionDescriptor{Issuer: s.issuer, UserMachineID: row.ID, UserMachineState: row.State, ExpiresAt: expires, Status: "connector_connecting", Reason: "connector_offline", RetryAfterSeconds: 2}
	setCanonicalMachineIdentity(&response, row)
	if row.State == "revoked" || row.State == "disconnected" || row.State == "deleted" || row.SeatState != "occupied" {
		response.Status = "user_machine_revoked"
		response.Reason = "access_revoked"
		return response, nil
	}
	route, routeErr := s.db.Queries().GetActiveHelperRouteForEnvironment(ctx, row.EnvironmentID)
	if errors.Is(routeErr, sql.ErrNoRows) {
		return response, nil
	}
	if routeErr != nil {
		return ConnectionDescriptor{}, routeErr
	}
	httpBaseURL, websocketBaseURL := "https://"+route.PublicHost, "wss://"+route.PublicHost
	if cliClientSessionID == "" || s.controlSigner == nil && s.credentials == nil {
		return ConnectionDescriptor{}, errors.New("user-machine credential issuer is unavailable")
	}
	input := access.CredentialInput{UserID: userID, ProjectID: row.ID, EnvironmentID: row.EnvironmentID, CLIClientSessionID: cliClientSessionID, HTTPBaseURL: httpBaseURL, ExpiresAt: expires}
	if s.controlSigner == nil {
		if err := s.credentials.CheckCLI(ctx, input); err != nil {
			return ConnectionDescriptor{}, err
		}
		if checker, ok := s.credentials.(interface {
			CheckHealth(context.Context, access.CredentialInput) error
		}); ok {
			if err := checker.CheckHealth(ctx, input); err != nil {
				response.Status = "connector_connecting"
				response.Reason = "helper_unhealthy"
				return response, nil
			}
		}
	}
	if err := s.applyTerminalSessionOperationsForSession(ctx, row.ID, terminalSession.ID); err != nil {
		response.Status = "helper_starting"
		response.Reason = "terminal_session_operation_pending"
		return response, nil
	}
	credentials, err := s.issueUserMachineCredentials(ctx, input, terminalSession.ID)
	if err != nil {
		return ConnectionDescriptor{}, err
	}
	if len(compactSessionIDs(credentials.TerminalSessionID, credentials.FileSessionID)) == 0 {
		return ConnectionDescriptor{}, errors.New("user-machine credential issuer returned no revocable sessions")
	}
	if err := s.db.Queries().CreateUserMachineAccessSession(ctx, dbsqlc.CreateUserMachineAccessSessionParams{
		ID: newID("umas"), UserMachineID: row.ID, UserID: userID, EnvironmentID: row.EnvironmentID,
		CLIClientSessionID: cliClientSessionID, HttpBaseUrl: httpBaseURL,
		HelperTerminalSessionID: credentials.TerminalSessionID, HelperFileSessionID: credentials.FileSessionID,
		ExpiresAt: expires,
	}); err != nil {
		cleanupErr := s.revokeCredentialSessions(ctx, machineAccessSession{
			UserID: userID, UserMachineID: row.ID, EnvironmentID: row.EnvironmentID,
			CLIClientSessionID: cliClientSessionID, HTTPBaseURL: httpBaseURL,
			TerminalSessionID: credentials.TerminalSessionID, FileSessionID: credentials.FileSessionID,
		}, "access_session_persistence_failed")
		return ConnectionDescriptor{}, errors.Join(err, cleanupErr)
	}
	response.Connectable, response.Status, response.Reason, response.RetryAfterSeconds = true, "ready", "ready", 0
	setCanonicalMachineIdentity(&response, row)
	response.Terminal = map[string]any{"protocol": "paperboat.terminal.v2", "endpoints": machineTerminalEndpoints(websocketBaseURL), "session_id": terminalSession.ID, "thread_id": terminalSession.ThreadID, "terminal_id": terminalSession.TerminalID, "cwd": terminalSession.LaunchCwd, "terminal_mode": terminalSession.TerminalMode, "auth": credentials.TerminalAuth}
	if credentials.FileTransferAuth != nil {
		response.FileTransfer = map[string]any{"endpoint": httpBaseURL + "/v1/file-transfers", "policy": s.fileTransferPolicy, "auth": credentials.FileTransferAuth}
	}
	return response, nil
}

func machineTerminalEndpoints(wss string) map[string]any {
	u, err := url.Parse(wss)
	if err != nil || u.Hostname() == "" {
		return map[string]any{}
	}
	host := u.Host
	if u.Port() == "" {
		host += ":443"
	}
	return map[string]any{"quic": "quic://" + host, "wss": "wss://" + u.Host + "/v1/runtime"}
}

func (s *Service) issueUserMachineCredentials(ctx context.Context, input access.CredentialInput, terminalSessionID string) (access.CLICredentials, error) {
	if s.controlSigner == nil {
		return s.credentials.IssueCLI(ctx, input)
	}
	issuedAt := s.now().UTC()
	terminalJTI := newID("jti_helper_terminal")
	transferJTI := newID("jti_helper_file_transfer")
	sign := func(class string, scopes []string, jti string) (string, error) {
		return s.controlSigner.SignCredential(mint.CredentialInput{
			Issuer: s.issuer, Audience: "paperboat-helper", Subject: input.UserID, JTI: jti,
			IssuedAt: issuedAt, ExpiresAt: input.ExpiresAt, CredentialClass: class, Scopes: scopes,
			EnvironmentID: input.EnvironmentID, UserID: input.UserID, CLIClientSessionID: input.CLIClientSessionID, SessionID: terminalSessionID,
		})
	}
	terminalToken, err := sign("terminal_operation", []string{"terminal:operate"}, terminalJTI)
	if err != nil {
		return access.CLICredentials{}, err
	}
	transferToken, err := sign("file_transfer", []string{"file:transfer"}, transferJTI)
	if err != nil {
		return access.CLICredentials{}, err
	}
	return access.CLICredentials{
		TerminalAuth:      map[string]any{"method": "bearer", "token": terminalToken, "expires_at": input.ExpiresAt, "scopes": []string{"terminal:operate"}},
		FileTransferAuth:  map[string]any{"method": "bearer", "token": transferToken, "expires_at": input.ExpiresAt, "scopes": []string{"file:transfer"}},
		TerminalSessionID: terminalJTI, FileSessionID: transferJTI,
	}, nil
}

func (s *Service) ConnectionReadiness(ctx context.Context, userID, userMachineID string) (ConnectionDescriptor, error) {
	return s.ConnectionReadinessForTerminalSession(ctx, userID, userMachineID, "")
}

func (s *Service) ConnectionReadinessForTerminalSession(ctx context.Context, userID, userMachineID, terminalSessionID string) (ConnectionDescriptor, error) {
	row, err := s.db.Queries().GetUserMachineForUser(ctx, dbsqlc.GetUserMachineForUserParams{ID: userMachineID, UserID: userID})
	if errors.Is(err, sql.ErrNoRows) {
		return ConnectionDescriptor{}, ErrNotFound
	}
	if err != nil {
		return ConnectionDescriptor{}, err
	}
	if _, err := s.terminalSession(ctx, userID, userMachineID, terminalSessionID); err != nil {
		return ConnectionDescriptor{}, err
	}
	response := ConnectionDescriptor{Issuer: s.issuer, UserMachineID: row.ID, UserMachineState: row.State, ExpiresAt: s.now().UTC(), Status: "connector_connecting", Reason: "connector_offline", RetryAfterSeconds: 2}
	setCanonicalMachineIdentity(&response, row)
	if row.State == "revoked" || row.State == "disconnected" || row.State == "deleted" || row.SeatState != "occupied" {
		response.Status = "user_machine_revoked"
		response.Reason = "access_revoked"
		return response, nil
	}
	if _, err := s.db.Queries().GetActiveHelperRouteForEnvironment(ctx, row.EnvironmentID); errors.Is(err, sql.ErrNoRows) {
		return response, nil
	} else if err != nil {
		return ConnectionDescriptor{}, err
	}
	response.Connectable, response.Status, response.Reason, response.RetryAfterSeconds = true, "ready", "ready", 0
	setCanonicalMachineIdentity(&response, row)
	return response, nil
}

func (s *Service) terminalSession(ctx context.Context, userID, userMachineID, sessionID string) (dbsqlc.UserMachineTerminalSession, error) {
	var (
		row dbsqlc.UserMachineTerminalSession
		err error
	)
	if strings.TrimSpace(sessionID) == "" {
		row, err = s.db.Queries().GetDefaultUserMachineTerminalSession(ctx, dbsqlc.GetDefaultUserMachineTerminalSessionParams{UserMachineID: userMachineID, UserID: userID})
	} else {
		row, err = s.db.Queries().GetUserMachineTerminalSession(ctx, dbsqlc.GetUserMachineTerminalSessionParams{ID: sessionID, UserMachineID: userMachineID, UserID: userID})
	}
	if errors.Is(err, sql.ErrNoRows) {
		return dbsqlc.UserMachineTerminalSession{}, ErrTerminalSessionNotFound
	}
	return row, err
}

func (s *Service) Approve(ctx context.Context, userID, userCode string) (UserMachine, error) {
	var out UserMachine
	var pairingID string
	var alreadyProvisioned bool
	var pairingExpired bool
	err := s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		pairing, err := tx.Queries().GetUserMachinePairingForCode(ctx, strings.TrimSpace(userCode))
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if pairing.State == "approved" && pairing.ApprovedByUserID.Valid && pairing.ApprovedByUserID.String == userID && pairing.UserMachineID.Valid {
			row, err := tx.Queries().GetUserMachineForUser(ctx, dbsqlc.GetUserMachineForUserParams{ID: pairing.UserMachineID.String, UserID: userID})
			if err != nil {
				return err
			}
			out, pairingID = mapMachine(row), pairing.ID
			alreadyProvisioned = len(pairing.InstallationConfigCiphertext) > 0
			return nil
		}
		if pairing.State != "pending" {
			return ErrPairingUsed
		}
		if !s.now().Before(pairing.ExpiresAt) {
			if _, err := tx.Queries().ExpireUserMachinePairing(ctx, pairing.ID); err != nil {
				return err
			}
			if enrollment, err := tx.Queries().GetUserMachineEnrollmentForPairingUpdate(ctx, sql.NullString{String: pairing.ID, Valid: true}); err == nil {
				if _, err := tx.Queries().ExpireUserMachineEnrollment(ctx, dbsqlc.ExpireUserMachineEnrollmentParams{ID: enrollment.ID, UserID: userID}); err != nil {
					return err
				}
			} else if !errors.Is(err, sql.ErrNoRows) {
				return err
			}
			pairingExpired = true
			return nil
		}
		enrollment, enrollmentErr := tx.Queries().GetUserMachineEnrollmentForPairingUpdate(ctx, sql.NullString{String: pairing.ID, Valid: true})
		if enrollmentErr == nil {
			if enrollment.UserID != userID || enrollment.State != "awaiting_approval" {
				return ErrNotFound
			}
		} else if !errors.Is(enrollmentErr, sql.ErrNoRows) {
			return enrollmentErr
		}
		if enrollmentErr == nil && enrollment.UserMachineID.Valid {
			row, err := tx.Queries().GetUserMachineForUser(ctx, dbsqlc.GetUserMachineForUserParams{ID: enrollment.UserMachineID.String, UserID: userID})
			if err != nil || row.State == "revoked" || row.State == "deleted" || row.SeatState != "released" || row.Platform != pairing.Platform || row.Architecture != pairing.Architecture || row.WorkspaceRoot != pairing.WorkspaceRoot || row.DisplayName != pairing.RequestedDisplayName {
				return ErrEnrollmentState
			}
			if s.seats == nil {
				return ErrSeatUnavailable
			}
			if err := s.seats.ReserveUserMachineSeat(ctx, tx, userID); err != nil {
				return err
			}
			if n, err := tx.Queries().OccupyUserMachineSeat(ctx, dbsqlc.OccupyUserMachineSeatParams{ID: row.ID, UserID: userID}); err != nil || n != 1 {
				if err != nil {
					return err
				}
				return ErrEnrollmentState
			}
			row.SeatState = "occupied"
			if n, err := tx.Queries().ApproveUserMachinePairing(ctx, dbsqlc.ApproveUserMachinePairingParams{UserID: sql.NullString{String: userID, Valid: true}, UserMachineID: sql.NullString{String: row.ID, Valid: true}, ID: pairing.ID}); err != nil || n != 1 {
				if err != nil {
					return err
				}
				return ErrPairingUsed
			}
			if n, err := tx.Queries().ApproveUserMachineEnrollment(ctx, dbsqlc.ApproveUserMachineEnrollmentParams{UserMachineID: sql.NullString{String: row.ID, Valid: true}, PairingID: sql.NullString{String: pairing.ID, Valid: true}, UserID: userID}); err != nil || n != 1 {
				if err != nil {
					return err
				}
				return ErrEnrollmentState
			}
			if err := s.ensureHelperRoute(ctx, tx, row.ID, row.EnvironmentID); err != nil {
				return err
			}
			out, pairingID = mapMachine(row), pairing.ID
			return s.audit.WriteTx(ctx, tx, audit.Event{ActorUserID: userID, ActorType: audit.ActorUser, EventType: "user_machine.installation_retried", ResourceType: "user_machine", ResourceID: row.ID, IdempotencyKey: "user_machine.installation_retried:" + pairing.ID, Metadata: map[string]any{"environment_id": row.EnvironmentID, "generation": enrollment.Generation}})
		}
		if s.seats == nil {
			return ErrSeatUnavailable
		}
		if err := s.seats.ReserveUserMachineSeat(ctx, tx, userID); err != nil {
			return err
		}
		row, err := tx.Queries().CreateUserMachine(ctx, dbsqlc.CreateUserMachineParams{ID: newID("um"), UserID: userID, EnvironmentID: newID("env"), DisplayName: pairing.RequestedDisplayName, Platform: pairing.Platform, Architecture: pairing.Architecture, WorkspaceRoot: pairing.WorkspaceRoot, RuntimeVersions: pairing.RuntimeVersions})
		if err != nil {
			return err
		}
		if _, err := tx.Queries().CreateControlEnvironment(ctx, dbsqlc.CreateControlEnvironmentParams{ID: row.EnvironmentID, WorkspaceID: row.ID, OwnerUserID: sql.NullString{String: userID, Valid: true}, DesiredState: "active"}); err != nil {
			return err
		}
		if err := s.ensureHelperRoute(ctx, tx, row.ID, row.EnvironmentID); err != nil {
			return err
		}
		if err := tx.Queries().CreateDefaultUserMachineTerminalSession(ctx, dbsqlc.CreateDefaultUserMachineTerminalSessionParams{ID: "umts_default_" + row.ID, UserMachineID: row.ID, LaunchCwd: row.WorkspaceRoot}); err != nil {
			return err
		}
		if _, err := s.ensureCurrentBandwidthPeriod(ctx, tx, row); err != nil {
			return err
		}
		if n, err := tx.Queries().ApproveUserMachinePairing(ctx, dbsqlc.ApproveUserMachinePairingParams{UserID: sql.NullString{String: userID, Valid: true}, UserMachineID: sql.NullString{String: row.ID, Valid: true}, ID: pairing.ID}); err != nil || n != 1 {
			if err != nil {
				return err
			}
			return ErrPairingUsed
		}
		if enrollmentErr == nil {
			n, err := tx.Queries().ApproveUserMachineEnrollment(ctx, dbsqlc.ApproveUserMachineEnrollmentParams{UserMachineID: sql.NullString{String: row.ID, Valid: true}, PairingID: sql.NullString{String: pairing.ID, Valid: true}, UserID: userID})
			if err != nil {
				return err
			}
			if n != 1 {
				return ErrEnrollmentState
			}
		}
		out = mapMachine(row)
		pairingID = pairing.ID
		return s.audit.WriteTx(ctx, tx, audit.Event{ActorUserID: userID, ActorType: audit.ActorUser, EventType: "user_machine.approved", ResourceType: "user_machine", ResourceID: row.ID, IdempotencyKey: "user_machine.approved:" + pairing.ID, Metadata: map[string]any{"platform": row.Platform, "architecture": row.Architecture}})
	})
	if pairingExpired {
		return UserMachine{}, ErrPairingExpired
	}
	if err != nil || alreadyProvisioned {
		return out, err
	}
	if s.helperGrant == nil {
		return UserMachine{}, ErrProvisioningUnavailable
	}
	if err := s.provisionApprovedUserMachine(ctx, userID, pairingID, out); err != nil {
		return UserMachine{}, err
	}
	return out, nil
}

func (s *Service) ensureHelperRoute(ctx context.Context, tx *db.Tx, userMachineID, environmentID string) error {
	if s.helperBaseDomain == "" || s.helperListenPort == 0 {
		return ErrProvisioningUnavailable
	}
	if _, err := tx.Queries().GetHelperRouteForEnvironment(ctx, environmentID); err == nil {
		return nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	publicHost := strings.ReplaceAll(strings.ToLower(userMachineID), "_", "-") + "." + s.helperBaseDomain
	_, err := tx.Queries().CreateControlRoute(ctx, dbsqlc.CreateControlRouteParams{
		ID: newID("rte"), EnvironmentID: environmentID, Kind: "helper_https_wss",
		PublicHost: publicHost, TargetHost: "127.0.0.1", TargetPort: s.helperListenPort,
	})
	return err
}

func (s *Service) Deny(ctx context.Context, userID, userCode string) error {
	userID, userCode = strings.TrimSpace(userID), strings.TrimSpace(userCode)
	if userID == "" || userCode == "" {
		return ErrNotFound
	}
	var pairingExpired bool
	err := s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		pairing, err := tx.Queries().GetUserMachinePairingForCode(ctx, userCode)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if pairing.State != "pending" {
			return ErrPairingUsed
		}
		if !s.now().Before(pairing.ExpiresAt) {
			if _, err := tx.Queries().ExpireUserMachinePairing(ctx, pairing.ID); err != nil {
				return err
			}
			if enrollment, err := tx.Queries().GetUserMachineEnrollmentForPairingUpdate(ctx, sql.NullString{String: pairing.ID, Valid: true}); err == nil {
				if _, err := tx.Queries().ExpireUserMachineEnrollment(ctx, dbsqlc.ExpireUserMachineEnrollmentParams{ID: enrollment.ID, UserID: userID}); err != nil {
					return err
				}
			} else if !errors.Is(err, sql.ErrNoRows) {
				return err
			}
			pairingExpired = true
			return nil
		}
		enrollment, err := tx.Queries().GetUserMachineEnrollmentForPairingUpdate(ctx, sql.NullString{String: pairing.ID, Valid: true})
		if errors.Is(err, sql.ErrNoRows) || err == nil && (enrollment.UserID != userID || enrollment.State != "awaiting_approval") {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if n, err := tx.Queries().DenyUserMachinePairing(ctx, dbsqlc.DenyUserMachinePairingParams{UserID: sql.NullString{String: userID, Valid: true}, ID: pairing.ID}); err != nil || n != 1 {
			if err != nil {
				return err
			}
			return ErrPairingUsed
		}
		if n, err := tx.Queries().DenyUserMachineEnrollment(ctx, dbsqlc.DenyUserMachineEnrollmentParams{PairingID: sql.NullString{String: pairing.ID, Valid: true}, UserID: userID}); err != nil || n != 1 {
			if err != nil {
				return err
			}
			return ErrEnrollmentState
		}
		return s.audit.WriteTx(ctx, tx, audit.Event{ActorUserID: userID, ActorType: audit.ActorUser, EventType: "user_machine.denied", ResourceType: "user_machine_enrollment", ResourceID: enrollment.ID, IdempotencyKey: "user_machine.denied:" + pairing.ID})
	})
	if pairingExpired && err == nil {
		return ErrPairingExpired
	}
	return err
}

func (s *Service) provisionApprovedUserMachine(ctx context.Context, userID, pairingID string, machine UserMachine) error {
	if strings.TrimSpace(s.encryptionKey) == "" {
		return errors.New("user-machine provisioning encryption is not configured")
	}
	if s.helperGrant == nil {
		return ErrProvisioningUnavailable
	}
	artifact, ok := s.helperArtifacts[machine.Platform+"-"+machine.Architecture+"-worker"]
	hostArtifact, hostOK := s.helperArtifacts[machine.Platform+"-"+machine.Architecture+"-host_service"]
	if !ok || !hostOK || s.artifactPublicKey == "" {
		return errors.New("user-machine helper artifact is unavailable")
	}
	enrollment, err := s.db.Queries().GetUserMachineEnrollmentForPairingUpdate(ctx, sql.NullString{String: pairingID, Valid: true})
	if err != nil {
		return err
	}
	var grant HelperEnrollmentGrant
	reuseIdentity := false
	if existing, existingErr := s.db.Queries().GetActiveControlHelperForEnvironment(ctx, machine.EnvironmentID); existingErr == nil {
		grant = HelperEnrollmentGrant{HelperID: existing.ID, ExpiresAt: s.now().UTC().Add(10 * time.Minute)}
		reuseIdentity = true
	} else if !errors.Is(existingErr, sql.ErrNoRows) {
		return existingErr
	} else {
		grant, err = s.helperGrant(ctx, userID, "byod-enrollment:"+pairingID, machine.EnvironmentID, 10*time.Minute)
		if err != nil {
			return err
		}
	}
	material, err := json.Marshal(map[string]any{
		"schema": "paperboat.byod-installation/v1", "user_machine_id": machine.ID, "user_machine_enrollment_id": enrollment.ID, "environment_id": machine.EnvironmentID,
		"control_url": s.issuer, "helper_id": grant.HelperID, "enrollment_id": grant.EnrollmentID,
		"enrollment_credential": grant.Credential, "reuse_identity": reuseIdentity, "expires_at": grant.ExpiresAt,
		"artifact": artifact, "host_service_artifact": hostArtifact, "artifact_public_key": s.artifactPublicKey,
		"helper_listen_address": fmt.Sprintf("127.0.0.1:%d", s.helperListenPort),
	})
	if err != nil {
		return err
	}
	ciphertext, err := secrets.Encrypt(s.encryptionKey, string(material))
	if err != nil {
		return err
	}
	return s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		n, err := tx.Queries().SetUserMachineInstallationConfig(ctx, dbsqlc.SetUserMachineInstallationConfigParams{ID: pairingID, Ciphertext: ciphertext})
		if err != nil {
			return err
		}
		if n != 1 {
			return ErrPairingUsed
		}
		_, err = tx.Queries().MarkUserMachineEnrollmentMaterialIssued(ctx, sql.NullString{String: pairingID, Valid: true})
		return err
	})
}

// ReserveBandwidth atomically grants capacity from the machine's included
// period allowance and then the owner's paid top-ups. It intentionally grants
// a partial amount when the requested window crosses exhaustion; the caller
// must stop forwarding once that grant is consumed.
func (s *Service) ReserveBandwidth(ctx context.Context, userMachineID string, requestedBytes int64) (BandwidthReservation, error) {
	if strings.TrimSpace(userMachineID) == "" {
		return BandwidthReservation{}, ErrNotFound
	}
	if requestedBytes <= 0 {
		return BandwidthReservation{}, ErrInvalidBandwidth
	}
	var reservation BandwidthReservation
	err := s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		machine, err := tx.Queries().GetUserMachineForBandwidthUpdate(ctx, strings.TrimSpace(userMachineID))
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		reservation, err = s.reserveBandwidthForMachineTx(ctx, tx, machine, requestedBytes, s.now().UTC(), true)
		return err
	})
	return reservation, err
}

// DebitEnvironmentBandwidthTx reconciles trusted edge usage against a BYOD
// environment inside the caller's transaction. Trusted reports are charged at
// the time their interval ended and remain chargeable after a machine disconnects
// or releases its seat. Hosted environments return a zero, non-exhausted result
// because they do not use the BYOD entitlement.
func (s *Service) DebitEnvironmentBandwidthTx(ctx context.Context, tx *db.Tx, environmentID string, bytes int64, now time.Time) (int64, bool, error) {
	if tx == nil || strings.TrimSpace(environmentID) == "" || bytes <= 0 {
		return 0, false, ErrInvalidBandwidth
	}
	machine, err := tx.Queries().GetUserMachineForEnvironmentBandwidthUpdate(ctx, strings.TrimSpace(environmentID))
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	reservation, err := s.reserveBandwidthForMachineTx(ctx, tx, machine, bytes, now.UTC(), false)
	return reservation.GrantedBytes, reservation.Exhausted, err
}

func (s *Service) reserveBandwidthForMachineTx(ctx context.Context, tx *db.Tx, machine dbsqlc.UserMachine, requestedBytes int64, now time.Time, requireActiveMachine bool) (BandwidthReservation, error) {
	if requireActiveMachine && (machine.State != "online" || machine.SeatState != "occupied") {
		return BandwidthReservation{}, ErrBandwidthDenied
	}
	period, err := s.ensureCurrentBandwidthPeriodAt(ctx, tx, machine, now)
	if err != nil {
		return BandwidthReservation{}, err
	}
	reservation := BandwidthReservation{}
	remaining := requestedBytes
	includedAvailable := period.IncludedBytes - period.ConsumedIncludedBytes
	if includedAvailable > 0 {
		consume := minInt64(remaining, includedAvailable)
		rows, err := tx.Queries().ConsumeUserMachineIncludedBandwidth(ctx, dbsqlc.ConsumeUserMachineIncludedBandwidthParams{ID: period.ID, Bytes: consume})
		if err != nil || rows != 1 {
			if err != nil {
				return BandwidthReservation{}, err
			}
			return BandwidthReservation{}, ErrBandwidthDenied
		}
		remaining -= consume
		reservation.GrantedBytes += consume
	}
	if remaining > 0 {
		topups, err := tx.Queries().ListActiveUserMachineTopupsForUpdate(ctx, machine.UserID)
		if err != nil {
			return BandwidthReservation{}, err
		}
		for _, topup := range topups {
			if remaining == 0 {
				break
			}
			consume := minInt64(remaining, topup.RemainingBytes)
			rows, err := tx.Queries().ConsumeUserMachineTopup(ctx, dbsqlc.ConsumeUserMachineTopupParams{ID: topup.ID, Bytes: consume})
			if err != nil || rows != 1 {
				if err != nil {
					return BandwidthReservation{}, err
				}
				return BandwidthReservation{}, ErrBandwidthDenied
			}
			remaining -= consume
			reservation.GrantedBytes += consume
		}
	}
	if reservation.GrantedBytes > 0 {
		topupBytes := reservation.GrantedBytes - minInt64(reservation.GrantedBytes, includedAvailable)
		rows, err := tx.Queries().RecordUserMachineTopupConsumption(ctx, dbsqlc.RecordUserMachineTopupConsumptionParams{ID: period.ID, Bytes: topupBytes})
		if err != nil || rows != 1 {
			if err != nil {
				return BandwidthReservation{}, err
			}
			return BandwidthReservation{}, ErrBandwidthDenied
		}
	}
	reservation.Exhausted = remaining > 0
	return reservation, nil
}

func (s *Service) ensureCurrentBandwidthPeriod(ctx context.Context, tx *db.Tx, machine dbsqlc.UserMachine) (dbsqlc.UserMachineBandwidthPeriod, error) {
	return s.ensureCurrentBandwidthPeriodAt(ctx, tx, machine, s.now().UTC())
}

func (s *Service) ensureCurrentBandwidthPeriodAt(ctx context.Context, tx *db.Tx, machine dbsqlc.UserMachine, now time.Time) (dbsqlc.UserMachineBandwidthPeriod, error) {
	entitlement, err := tx.Queries().GetUserMachineEntitlementForUpdate(ctx, machine.UserID)
	if errors.Is(err, sql.ErrNoRows) {
		return dbsqlc.UserMachineBandwidthPeriod{}, ErrBandwidthDenied
	}
	if err != nil {
		return dbsqlc.UserMachineBandwidthPeriod{}, err
	}
	if (entitlement.State != "active" && entitlement.State != "trialing") || !now.Before(entitlement.CurrentPeriodEnd) || now.Before(entitlement.CurrentPeriodStart) {
		return dbsqlc.UserMachineBandwidthPeriod{}, ErrBandwidthDenied
	}
	return tx.Queries().UpsertUserMachineBandwidthPeriod(ctx, dbsqlc.UpsertUserMachineBandwidthPeriodParams{ID: newID("umbp"), UserMachineID: machine.ID, PeriodStart: entitlement.CurrentPeriodStart, PeriodEnd: entitlement.CurrentPeriodEnd, IncludedBytes: entitlement.AllowanceBytes})
}

func minInt64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func (s *Service) List(ctx context.Context, userID string, limit, offset int) ([]UserMachine, int, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	rows, err := s.db.Queries().ListUserMachinesForUser(ctx, dbsqlc.ListUserMachinesForUserParams{UserID: userID, PageLimit: int32(limit), PageOffset: int32(offset)})
	if err != nil {
		return nil, 0, err
	}
	total, err := s.db.Queries().CountUserMachinesForUser(ctx, userID)
	if err != nil {
		return nil, 0, err
	}
	out := make([]UserMachine, 0, len(rows))
	for _, row := range rows {
		out = append(out, mapMachine(row))
	}
	return out, int(total), nil
}

func (s *Service) Get(ctx context.Context, userID, userMachineID string) (UserMachine, error) {
	row, err := s.db.Queries().GetUserMachineForUser(ctx, dbsqlc.GetUserMachineForUserParams{ID: userMachineID, UserID: userID})
	if errors.Is(err, sql.ErrNoRows) {
		return UserMachine{}, ErrNotFound
	}
	if err != nil {
		return UserMachine{}, err
	}
	return mapMachine(row), nil
}

func (s *Service) ListTerminalSessions(ctx context.Context, userID, userMachineID string) ([]TerminalSession, error) {
	if _, err := s.Get(ctx, userID, userMachineID); err != nil {
		return nil, err
	}
	rows, err := s.db.Queries().ListUserMachineTerminalSessions(ctx, dbsqlc.ListUserMachineTerminalSessionsParams{UserMachineID: userMachineID, UserID: userID})
	if err != nil {
		return nil, err
	}
	out := make([]TerminalSession, 0, len(rows))
	for _, row := range rows {
		out = append(out, mapTerminalSession(row))
	}
	return out, nil
}

func (s *Service) CreateTerminalSession(ctx context.Context, userID, userMachineID, name, idempotencyKey string, maxActive int) (TerminalSession, error) {
	return s.CreateTerminalSessionWithMode(ctx, userID, userMachineID, name, "herdr", idempotencyKey, maxActive)
}

func (s *Service) CreateTerminalSessionWithMode(ctx context.Context, userID, userMachineID, name, terminalMode, idempotencyKey string, maxActive int) (TerminalSession, error) {
	requestedName := strings.ToLower(strings.TrimSpace(name))
	if requestedName != "" && !validUserMachineTerminalSessionName(requestedName) {
		return TerminalSession{}, ErrTerminalSessionInvalidName
	}
	if strings.TrimSpace(idempotencyKey) == "" {
		return TerminalSession{}, ErrTerminalSessionIdempotency
	}
	terminalMode = strings.TrimSpace(terminalMode)
	if terminalMode == "" {
		terminalMode = "herdr"
	}
	if terminalMode != "herdr" && terminalMode != "shell" {
		return TerminalSession{}, ErrTerminalSessionInvalidMode
	}
	if maxActive <= 0 {
		return TerminalSession{}, ErrTerminalSessionLimit
	}
	if existing, err := s.db.Queries().GetUserMachineTerminalSessionByIdempotencyKey(ctx, dbsqlc.GetUserMachineTerminalSessionByIdempotencyKeyParams{UserMachineID: userMachineID, UserID: userID, IdempotencyKey: sql.NullString{String: idempotencyKey, Valid: true}}); err == nil {
		if existing.TerminalMode != terminalMode {
			return TerminalSession{}, ErrTerminalSessionConflict
		}
		return mapTerminalSession(existing), nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return TerminalSession{}, err
	}
	machine, err := s.db.Queries().GetUserMachineForUser(ctx, dbsqlc.GetUserMachineForUserParams{ID: userMachineID, UserID: userID})
	if errors.Is(err, sql.ErrNoRows) {
		return TerminalSession{}, ErrNotFound
	}
	if err != nil {
		return TerminalSession{}, err
	}
	id, terminalID := newID("umts"), newID("term")
	var evictedSession *TerminalSession
	err = s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		if _, err := tx.Queries().LockUserMachineTerminalSessions(ctx, dbsqlc.LockUserMachineTerminalSessionsParams{UserMachineID: userMachineID, UserID: userID}); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		if existing, err := tx.Queries().GetUserMachineTerminalSessionByIdempotencyKey(ctx, dbsqlc.GetUserMachineTerminalSessionByIdempotencyKeyParams{UserMachineID: userMachineID, UserID: userID, IdempotencyKey: sql.NullString{String: idempotencyKey, Valid: true}}); err == nil {
			if existing.TerminalMode != terminalMode {
				return ErrTerminalSessionConflict
			}
			id, terminalID = existing.ID, existing.TerminalID
			return nil
		} else if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		count, err := tx.Queries().CountActiveUserMachineTerminalSessions(ctx, userMachineID)
		if err != nil {
			return err
		}
		if int(count) >= maxActive {
			evicted, selectErr := tx.Queries().SelectUserMachineTerminalSessionForEviction(ctx, userMachineID)
			if selectErr != nil {
				if errors.Is(selectErr, sql.ErrNoRows) {
					return ErrTerminalSessionLimit
				}
				return selectErr
			}
			if _, err = tx.Queries().DeleteUserMachineTerminalSession(ctx, dbsqlc.DeleteUserMachineTerminalSessionParams{UserMachineID: userMachineID, ID: evicted.ID}); err != nil {
				return err
			}
			mapped := mapTerminalSession(evicted)
			evictedSession = &mapped
			if err = tx.Queries().QueueUserMachineTerminalSessionOperation(ctx, dbsqlc.QueueUserMachineTerminalSessionOperationParams{ID: newID("umtso"), UserMachineID: userMachineID, TerminalSessionID: evicted.ID, Operation: "delete_history"}); err != nil {
				return err
			}
		}
		sessionName := requestedName
		ordinal := int32(0)
		if sessionName == "" {
			ordinal, err = tx.Queries().NextUserMachineTerminalSessionOrdinal(ctx, userMachineID)
			if err != nil {
				return err
			}
			sessionName = fmt.Sprintf("shell-%d", ordinal)
		}
		return tx.Queries().CreateUserMachineTerminalSession(ctx, dbsqlc.CreateUserMachineTerminalSessionParams{ID: id, UserMachineID: userMachineID, TerminalID: terminalID, Name: sessionName, AutoNameOrdinal: ordinal, IdempotencyKey: sql.NullString{String: idempotencyKey, Valid: true}, LaunchCwd: machine.WorkspaceRoot, TerminalMode: terminalMode})
	})
	if err != nil {
		if userMachineTerminalSessionUniqueViolation(err) {
			existing, lookupErr := s.db.Queries().GetUserMachineTerminalSessionByIdempotencyKey(ctx, dbsqlc.GetUserMachineTerminalSessionByIdempotencyKeyParams{UserMachineID: userMachineID, UserID: userID, IdempotencyKey: sql.NullString{String: idempotencyKey, Valid: true}})
			if lookupErr == nil {
				if existing.TerminalMode != terminalMode {
					return TerminalSession{}, ErrTerminalSessionConflict
				}
				return mapTerminalSession(existing), nil
			}
			if !errors.Is(lookupErr, sql.ErrNoRows) {
				return TerminalSession{}, lookupErr
			}
			return TerminalSession{}, ErrTerminalSessionConflict
		}
		return TerminalSession{}, err
	}
	row, err := s.db.Queries().GetUserMachineTerminalSession(ctx, dbsqlc.GetUserMachineTerminalSessionParams{ID: id, UserMachineID: userMachineID, UserID: userID})
	if err != nil {
		return TerminalSession{}, err
	}
	created := mapTerminalSession(row)
	created.EvictedSession = evictedSession
	return created, nil
}

func userMachineTerminalSessionUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

func (s *Service) CreateConfiguredTerminalSession(ctx context.Context, userID, userMachineID, name, idempotencyKey string) (TerminalSession, error) {
	return s.CreateTerminalSession(ctx, userID, userMachineID, name, idempotencyKey, s.maxSessions)
}

func (s *Service) CreateConfiguredTerminalSessionWithMode(ctx context.Context, userID, userMachineID, name, terminalMode, idempotencyKey string) (TerminalSession, error) {
	return s.CreateTerminalSessionWithMode(ctx, userID, userMachineID, name, terminalMode, idempotencyKey, s.maxSessions)
}

func (s *Service) RenameTerminalSession(ctx context.Context, userID, userMachineID, id, name string) (TerminalSession, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	if !validUserMachineTerminalSessionName(name) {
		return TerminalSession{}, ErrTerminalSessionInvalidName
	}
	n, err := s.db.Queries().RenameUserMachineTerminalSession(ctx, dbsqlc.RenameUserMachineTerminalSessionParams{UserMachineID: userMachineID, ID: id, Name: name})
	if err != nil {
		return TerminalSession{}, err
	}
	if n == 0 {
		row, lookupErr := s.db.Queries().GetUserMachineTerminalSession(ctx, dbsqlc.GetUserMachineTerminalSessionParams{ID: id, UserMachineID: userMachineID, UserID: userID})
		if errors.Is(lookupErr, sql.ErrNoRows) {
			return TerminalSession{}, ErrTerminalSessionNotFound
		}
		if lookupErr != nil {
			return TerminalSession{}, lookupErr
		}
		if row.IsDefault {
			return TerminalSession{}, ErrTerminalSessionReserved
		}
		return TerminalSession{}, ErrTerminalSessionConflict
	}
	row, err := s.db.Queries().GetUserMachineTerminalSession(ctx, dbsqlc.GetUserMachineTerminalSessionParams{ID: id, UserMachineID: userMachineID, UserID: userID})
	if err != nil {
		return TerminalSession{}, err
	}
	return mapTerminalSession(row), nil
}

func validUserMachineTerminalSessionName(name string) bool {
	return name != "default" && !automaticTerminalNamePattern.MatchString(name) && terminalSessionNamePattern.MatchString(name)
}

// CloseTerminalSession queues a signed Helper control operation. It returns
// false when the operation is durable but the connector is offline, allowing
// the HTTP handler to report an accepted/pending result instead of discarding
// the user's request.
func (s *Service) CloseTerminalSession(ctx context.Context, userID, userMachineID, id string) (bool, error) {
	if _, err := s.db.Queries().GetUserMachineTerminalSession(ctx, dbsqlc.GetUserMachineTerminalSessionParams{ID: id, UserMachineID: userMachineID, UserID: userID}); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, ErrTerminalSessionNotFound
		}
		return false, err
	}
	n, err := s.db.Queries().CloseUserMachineTerminalSession(ctx, dbsqlc.CloseUserMachineTerminalSessionParams{UserMachineID: userMachineID, ID: id})
	if err != nil {
		return false, err
	}
	if n > 0 {
		if err := s.db.Queries().QueueUserMachineTerminalSessionOperation(ctx, dbsqlc.QueueUserMachineTerminalSessionOperationParams{ID: newID("umtso"), UserMachineID: userMachineID, TerminalSessionID: id, Operation: "close"}); err != nil {
			return false, err
		}
	}
	if err := s.ApplyTerminalSessionOperations(ctx, userMachineID); err != nil {
		return false, nil
	}
	return true, nil
}

func (s *Service) DeleteTerminalSession(ctx context.Context, userID, userMachineID, id string) (bool, error) {
	row, err := s.db.Queries().GetUserMachineTerminalSession(ctx, dbsqlc.GetUserMachineTerminalSessionParams{ID: id, UserMachineID: userMachineID, UserID: userID})
	if errors.Is(err, sql.ErrNoRows) {
		return false, ErrTerminalSessionNotFound
	}
	if err != nil {
		return false, err
	}
	if row.IsDefault {
		return false, ErrTerminalSessionReserved
	}
	n, err := s.db.Queries().DeleteUserMachineTerminalSession(ctx, dbsqlc.DeleteUserMachineTerminalSessionParams{UserMachineID: userMachineID, ID: id})
	if err != nil {
		return false, err
	}
	if n == 0 {
		return false, ErrTerminalSessionNotFound
	}
	if err := s.db.Queries().QueueUserMachineTerminalSessionOperation(ctx, dbsqlc.QueueUserMachineTerminalSessionOperationParams{ID: newID("umtso"), UserMachineID: userMachineID, TerminalSessionID: id, Operation: "delete_history"}); err != nil {
		return false, err
	}
	if err := s.ApplyTerminalSessionOperations(ctx, userMachineID); err != nil {
		return false, nil
	}
	return true, nil
}

func (s *Service) ApplyTerminalSessionOperations(ctx context.Context, userMachineID string) error {
	return s.applyTerminalSessionOperations(ctx, userMachineID, "")
}

func (s *Service) applyTerminalSessionOperationsForSession(ctx context.Context, userMachineID, terminalSessionID string) error {
	return s.applyTerminalSessionOperations(ctx, userMachineID, terminalSessionID)
}

func (s *Service) applyTerminalSessionOperations(ctx context.Context, userMachineID, terminalSessionID string) error {
	for {
		items, err := s.db.Queries().ListPendingUserMachineTerminalSessionOperations(ctx, dbsqlc.ListPendingUserMachineTerminalSessionOperationsParams{UserMachineID: userMachineID, BatchSize: 32})
		if err != nil {
			return err
		}
		if len(items) == 0 {
			return nil
		}
		for _, item := range items {
			if terminalSessionID != "" && item.TerminalSessionID != terminalSessionID {
				continue
			}
			if err := s.applyTerminalSessionOperation(ctx, item.ID, item.UserMachineID, item.TerminalSessionID, item.Operation, item.Attempts, item.UserID, item.EnvironmentID, item.ProviderRouteHttpBaseUrl); err != nil {
				return err
			}
		}
		if terminalSessionID != "" {
			return nil
		}
	}
}

func (s *Service) processDueTerminalSessionOperations(ctx context.Context) error {
	items, err := s.db.Queries().ListDueUserMachineTerminalSessionOperations(ctx, 32)
	if err != nil {
		return err
	}
	var errs []error
	for _, item := range items {
		if err := s.applyTerminalSessionOperation(ctx, item.ID, item.UserMachineID, item.TerminalSessionID, item.Operation, item.Attempts, item.UserID, item.EnvironmentID, item.ProviderRouteHttpBaseUrl); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (s *Service) applyTerminalSessionOperation(ctx context.Context, operationID, userMachineID, terminalSessionID, operation string, attempts int32, userID, environmentID, route string) error {
	if s.controlSigner == nil || s.controlRuntime == nil || strings.TrimSpace(route) == "" || strings.TrimSpace(s.issuer) == "" {
		return s.retryTerminalSessionOperation(ctx, operationID, attempts, errors.New("user-machine terminal control is unavailable"))
	}
	now := s.now().UTC()
	credential, err := s.controlSigner.SignCredential(mint.CredentialInput{
		Issuer: s.issuer, Audience: "paperboat-helper", Subject: userID, JTI: newID("jti"),
		IssuedAt: now, ExpiresAt: now.Add(mint.MaxProofTTL), CredentialClass: "terminal_operation", Scopes: []string{"terminal:operate"},
		EnvironmentID: environmentID, UserID: userID, CLIClientSessionID: operationID, SessionID: terminalSessionID,
	})
	if err == nil {
		action := operation
		if action == "delete_history" {
			action = "delete"
		}
		var observed helperruntime.Snapshot
		observed, err = s.controlRuntime.Terminal(ctx, route, credential, action, terminalSessionID, operationID)
		if err == nil && action == "close" && observed.State != "closed" {
			err = fmt.Errorf("helper runtime acknowledged close in state %q", observed.State)
		}
		if err == nil && action == "close" {
			err = s.db.Queries().MarkUserMachineTerminalSessionRuntimeClosed(ctx, terminalSessionID)
		}
	}
	if err != nil {
		return s.retryTerminalSessionOperation(ctx, operationID, attempts, err)
	}
	return s.db.Queries().MarkUserMachineTerminalSessionOperationApplied(ctx, operationID)
}

func (s *Service) retryTerminalSessionOperation(ctx context.Context, id string, attempts int32, cause error) error {
	multiplier := 1 << minInt(8, int(attempts))
	backoff := multiplier
	if backoff > 300 {
		backoff = 300
	}
	err := s.db.Queries().RetryUserMachineTerminalSessionOperation(ctx, dbsqlc.RetryUserMachineTerminalSessionOperationParams{ID: id, RetrySeconds: float64(backoff), LastError: sql.NullString{String: truncateTerminalError(cause), Valid: true}})
	return errors.Join(cause, err)
}

func truncateTerminalError(err error) string {
	value := err.Error()
	if len(value) > 500 {
		return value[:500]
	}
	return value
}

func minInt(left, right int) int {
	if left < right {
		return left
	}
	return right
}

func mapTerminalSession(row dbsqlc.UserMachineTerminalSession) TerminalSession {
	session := TerminalSession{ID: row.ID, Name: row.Name, IsDefault: row.IsDefault, State: row.DesiredState, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt, TerminalMode: row.TerminalMode}
	if row.LastActivityAt.Valid {
		value := row.LastActivityAt.Time
		session.LastActiveAt = &value
	}
	return session
}

// Disconnect explicitly revokes the local enrollment and releases its seat.
// Offline status is intentionally not treated as disconnect.
func (s *Service) Disconnect(ctx context.Context, userID, userMachineID string) error {
	if err := s.revokeUserMachineControl(ctx, userID, userMachineID, false); err != nil {
		return err
	}
	auditErr := s.audit.Write(ctx, audit.Event{ActorUserID: userID, ActorType: audit.ActorUser, EventType: "user_machine.disconnected", ResourceType: "user_machine", ResourceID: userMachineID, IdempotencyKey: "user_machine.disconnected:" + userMachineID, Metadata: map[string]any{}})
	return errors.Join(auditErr, s.RevokeUserMachineSessions(ctx, userMachineID, "user_machine_disconnected"))
}

func (s *Service) Delete(ctx context.Context, userID, userMachineID string) error {
	if err := s.revokeUserMachineControl(ctx, userID, userMachineID, true); err != nil {
		return err
	}
	auditErr := s.audit.Write(ctx, audit.Event{ActorUserID: userID, ActorType: audit.ActorUser, EventType: "user_machine.deleted", ResourceType: "user_machine", ResourceID: userMachineID, IdempotencyKey: "user_machine.deleted:" + userMachineID, Metadata: map[string]any{}})
	return errors.Join(auditErr, s.RevokeUserMachineSessions(ctx, userMachineID, "user_machine_deleted"))
}

func (s *Service) revokeUserMachineControl(ctx context.Context, userID, userMachineID string, deleted bool) error {
	now := s.now().UTC()
	return s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		machine, err := tx.Queries().GetUserMachineForUpdate(ctx, dbsqlc.GetUserMachineForUpdateParams{ID: userMachineID, UserID: userID})
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		var changed int64
		if deleted {
			changed, err = tx.Queries().DeleteUserMachine(ctx, dbsqlc.DeleteUserMachineParams{ID: userMachineID, UserID: userID})
		} else {
			changed, err = tx.Queries().RevokeUserMachine(ctx, dbsqlc.RevokeUserMachineParams{ID: userMachineID, UserID: userID, State: "disconnected", SeatState: "released"})
		}
		if err != nil {
			return err
		}
		if changed != 1 {
			return ErrNotFound
		}
		return s.revokeEnvironmentControlTx(ctx, tx, machine.EnvironmentID, now)
	})
}

func (s *Service) revokeEnvironmentControlTx(ctx context.Context, tx *db.Tx, environmentID string, now time.Time) error {
	environment, err := tx.Queries().GetControlEnvironment(ctx, environmentID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err == nil && environment.DesiredState != "revoked" {
		if _, err := tx.Queries().UpdateControlEnvironmentDesiredState(ctx, dbsqlc.UpdateControlEnvironmentDesiredStateParams{DesiredState: "revoked", Now: now, ID: environmentID, ExpectedVersion: environment.DesiredVersion}); err != nil {
			return err
		}
	}
	if _, err := tx.Queries().RevokeControlHelpersForEnvironment(ctx, dbsqlc.RevokeControlHelpersForEnvironmentParams{RevokedAt: now, EnvironmentID: environmentID}); err != nil {
		return err
	}
	if _, err := tx.Queries().RevokeControlHelperEnrollmentsForEnvironment(ctx, dbsqlc.RevokeControlHelperEnrollmentsForEnvironmentParams{RevokedAt: sql.NullTime{Time: now, Valid: true}, EnvironmentID: environmentID}); err != nil {
		return err
	}
	if _, err := tx.Queries().RevokeControlConnectorForEnvironment(ctx, dbsqlc.RevokeControlConnectorForEnvironmentParams{RevokedAt: now, EnvironmentID: environmentID}); err != nil {
		return err
	}
	if _, err := tx.Queries().RevokeControlRoutesForEnvironment(ctx, dbsqlc.RevokeControlRoutesForEnvironmentParams{EnvironmentID: environmentID, Now: now}); err != nil {
		return err
	}
	if _, err = tx.Queries().RevokeControlConfigCredentialsForEnvironment(ctx, dbsqlc.RevokeControlConfigCredentialsForEnvironmentParams{EnvironmentID: environmentID, RevokedAt: sql.NullTime{Time: now, Valid: true}}); err != nil {
		return err
	}
	if _, err = tx.Queries().RevokeControlConfigRepositoryAccessForEnvironment(ctx, dbsqlc.RevokeControlConfigRepositoryAccessForEnvironmentParams{EnvironmentID: environmentID, Now: now}); err != nil {
		return err
	}
	_, err = tx.Queries().RevokeControlConfigRepositoryLeasesForEnvironment(ctx, dbsqlc.RevokeControlConfigRepositoryLeasesForEnvironmentParams{EnvironmentID: sql.NullString{String: environmentID, Valid: true}, Now: sql.NullTime{Time: now, Valid: true}})
	return err
}

// RevokeUserMachineSessions records revocation before attempting the downstream
// call. Failed calls remain pending for Worker so revocation is eventually
// propagated without keeping the user's disconnect action hostage to an
// offline connector.
func (s *Service) RevokeUserMachineSessions(ctx context.Context, userMachineID, reason string) error {
	if strings.TrimSpace(userMachineID) == "" || strings.TrimSpace(reason) == "" {
		return errors.New("user-machine revocation input is incomplete")
	}
	rows, err := s.db.Queries().RevokeUserMachineAccessSessions(ctx, dbsqlc.RevokeUserMachineAccessSessionsParams{
		UserMachineID: userMachineID, Reason: sql.NullString{String: reason, Valid: true},
	})
	if err != nil {
		return err
	}
	var errs []error
	for _, row := range rows {
		if err := s.revokeCredentialSessions(ctx, machineAccessSession{ID: row.ID, UserID: row.UserID, UserMachineID: row.UserMachineID, EnvironmentID: row.EnvironmentID, CLIClientSessionID: row.CLIClientSessionID, HTTPBaseURL: row.HttpBaseUrl, TerminalSessionID: row.HelperTerminalSessionID, FileSessionID: row.HelperFileSessionID}, reason); err != nil {
			errs = append(errs, err)
			continue
		}
		if _, err := s.db.Queries().MarkUserMachineAccessSessionRevoked(ctx, row.ID); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// RevokeUserSessions is called after an entitlement revocation. It has the
// same durable retry behavior as an explicit machine disconnect.
func (s *Service) RevokeUserSessions(ctx context.Context, userID, reason string) error {
	if strings.TrimSpace(userID) == "" || strings.TrimSpace(reason) == "" {
		return errors.New("user-machine user revocation input is incomplete")
	}
	rows, err := s.db.Queries().RevokeUserMachineAccessSessionsForUser(ctx, dbsqlc.RevokeUserMachineAccessSessionsForUserParams{UserID: userID, Reason: sql.NullString{String: reason, Valid: true}})
	if err != nil {
		return err
	}
	var errs []error
	for _, row := range rows {
		if err := s.revokeCredentialSessions(ctx, machineAccessSession{ID: row.ID, UserID: row.UserID, UserMachineID: row.UserMachineID, EnvironmentID: row.EnvironmentID, CLIClientSessionID: row.CLIClientSessionID, HTTPBaseURL: row.HttpBaseUrl, TerminalSessionID: row.HelperTerminalSessionID, FileSessionID: row.HelperFileSessionID}, reason); err != nil {
			errs = append(errs, err)
			continue
		}
		if _, err := s.db.Queries().MarkUserMachineAccessSessionRevoked(ctx, row.ID); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// ReconcileUserMachineEntitlement is safe to call after every billing
// webhook. It revokes all machines after entitlement loss and the newest
// excess machines after a seat reduction.
func (s *Service) ReconcileUserMachineEntitlement(ctx context.Context, userID string) error {
	if strings.TrimSpace(userID) == "" {
		return errors.New("user-machine entitlement user is required")
	}
	now := s.now().UTC()
	var revokedMachineIDs []string
	active := false
	if err := s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		seatQuantity, err := tx.Queries().GetActiveUserMachineSeatQuantity(ctx, userID)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if err == nil {
			active = true
			machines, err := tx.Queries().RevokeUserMachinesOverSeatLimit(ctx, dbsqlc.RevokeUserMachinesOverSeatLimitParams{
				UserID: userID, SeatQuantity: seatQuantity,
			})
			if err != nil {
				return err
			}
			for _, machine := range machines {
				revokedMachineIDs = append(revokedMachineIDs, machine.ID)
				if err := s.revokeEnvironmentControlTx(ctx, tx, machine.EnvironmentID, now); err != nil {
					return err
				}
			}
			return nil
		}
		environments, err := tx.Queries().ListRevokedUserMachineEnvironmentsForUser(ctx, userID)
		if err != nil {
			return err
		}
		for _, environment := range environments {
			if err := s.revokeEnvironmentControlTx(ctx, tx, environment.EnvironmentID, now); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return err
	}
	if active {
		var errs []error
		for _, userMachineID := range revokedMachineIDs {
			errs = append(errs, s.RevokeUserMachineSessions(ctx, userMachineID, "user_machine_seat_released"))
		}
		return errors.Join(errs...)
	}
	return s.RevokeUserSessions(ctx, userID, "user_machine_entitlement_revoked")
}

// RetryPendingRevocations is intentionally idempotent. Helper's signed
// revocation endpoint accepts repeated session IDs, and marking propagation is
// conditional on a still-pending row.
func (s *Service) RetryPendingRevocations(ctx context.Context) error {
	rows, err := s.db.Queries().ListPendingUserMachineAccessSessionRevocations(ctx)
	if err != nil {
		return err
	}
	var errs []error
	for _, row := range rows {
		reason := "revoked"
		if row.RevocationReason.Valid && strings.TrimSpace(row.RevocationReason.String) != "" {
			reason = row.RevocationReason.String
		}
		if err := s.revokeCredentialSessions(ctx, machineAccessSession{ID: row.ID, UserID: row.UserID, UserMachineID: row.UserMachineID, EnvironmentID: row.EnvironmentID, CLIClientSessionID: row.CLIClientSessionID, HTTPBaseURL: row.HttpBaseUrl, TerminalSessionID: row.HelperTerminalSessionID, FileSessionID: row.HelperFileSessionID}, reason); err != nil {
			errs = append(errs, err)
			continue
		}
		if _, err := s.db.Queries().MarkUserMachineAccessSessionRevoked(ctx, row.ID); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

type machineAccessSession struct {
	ID, UserID, UserMachineID, EnvironmentID, CLIClientSessionID, HTTPBaseURL string
	TerminalSessionID, FileSessionID                                          string
}

func (s *Service) revokeCredentialSessions(ctx context.Context, session machineAccessSession, reason string) error {
	sessionIDs := compactSessionIDs(session.TerminalSessionID, session.FileSessionID)
	if len(sessionIDs) == 0 {
		return nil
	}
	canonical := true
	for _, sessionID := range sessionIDs {
		canonical = canonical && strings.HasPrefix(sessionID, "jti_helper_")
	}
	if canonical {
		// Helper credentials are short-lived signed tokens. Environment route and
		// helper revocation fence them immediately; no downstream issuer exists.
		return nil
	}
	if s.credentials == nil {
		return errors.New("user-machine credential issuer is unavailable")
	}
	if err := s.credentials.RevokeCLI(ctx, access.CredentialRevocationInput{
		UserID: session.UserID, ProjectID: session.UserMachineID, EnvironmentID: session.EnvironmentID,
		CLIClientSessionID: session.CLIClientSessionID, HTTPBaseURL: session.HTTPBaseURL,
		SessionIDs: sessionIDs, Reason: reason,
	}); err != nil {
		return fmt.Errorf("revoke user-machine sessions for %s: %w", session.UserMachineID, err)
	}
	return nil
}

func compactSessionIDs(values ...string) []string {
	ids := make([]string, 0, len(values))
	for _, value := range values {
		if value != "" && !slices.Contains(ids, value) {
			ids = append(ids, value)
		}
	}
	return ids
}

func (s *Service) validatePairing(in PairingInput) error {
	token := strings.TrimSpace(in.EnrollmentToken)
	if s.policy.PairingLifetime <= 0 || strings.TrimSpace(in.Verifier) == "" || strings.TrimSpace(in.DisplayName) == "" || strings.TrimSpace(in.Architecture) == "" || !filepath.IsAbs(in.WorkspaceRoot) || filepath.Clean(in.WorkspaceRoot) != in.WorkspaceRoot || !slices.Contains(s.policy.AllowedPlatforms, strings.ToLower(strings.TrimSpace(in.Platform))) || token != "" && (len(token) < 32 || len(token) > 256) {
		return ErrInvalidPairing
	}
	return nil
}
func mapMachine(row dbsqlc.UserMachine) UserMachine {
	diagnostics := RuntimeDiagnostics{WorkerGeneration: uint64(row.WorkerGeneration), OSBootID: row.OsBootID.String, WorkerServiceScope: row.WorkerServiceScope, ConnectorState: row.ConnectorState, ConnectorGeneration: uint64(row.ConnectorGeneration)}
	if row.RuntimeDiagnosticsObservedAt.Valid {
		observed := row.RuntimeDiagnosticsObservedAt.Time
		diagnostics.ObservedAt = &observed
	}
	m := UserMachine{ID: row.ID, EnvironmentID: row.EnvironmentID, DisplayName: row.DisplayName, Platform: row.Platform, Architecture: row.Architecture, WorkspaceRoot: row.WorkspaceRoot, State: row.State, SeatState: row.SeatState, Online: row.Online, RuntimeVersions: row.RuntimeVersions, Availability: mapAvailability(row), RuntimeDiagnostics: diagnostics}
	if row.EnrolledAt.Valid {
		v := row.EnrolledAt.Time
		m.EnrolledAt = &v
	}
	if row.LastSeenAt.Valid {
		v := row.LastSeenAt.Time
		m.LastSeenAt = &v
	}
	return m
}
func newID(prefix string) string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return prefix + "_" + hex.EncodeToString(b[:])
}
func randomCode(length int) (string, error) {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, length)
	raw := make([]byte, length)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = alphabet[int(raw[i])%len(alphabet)]
	}
	return string(b), nil
}
