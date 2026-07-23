package connectedmachines

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

	"github.com/pinksaucepasta/paperboat-server/internal/accessdescriptor"
	"github.com/pinksaucepasta/paperboat-server/internal/agentunnel"
	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
	"github.com/pinksaucepasta/paperboat-server/internal/helperruntime"
	"github.com/pinksaucepasta/paperboat-server/internal/mint"
	"github.com/pinksaucepasta/paperboat-server/internal/secrets"
)

var (
	ErrInvalidPairing             = errors.New("invalid connected-machine pairing")
	ErrPairingExpired             = errors.New("connected-machine pairing expired")
	ErrPairingUsed                = errors.New("connected-machine pairing is no longer pending")
	ErrSeatUnavailable            = errors.New("connected-machine seat unavailable")
	ErrNotFound                   = errors.New("connected machine not found")
	ErrBandwidthDenied            = errors.New("connected-machine bandwidth is unavailable")
	ErrInvalidBandwidth           = errors.New("connected-machine bandwidth request is invalid")
	ErrInstallationPending        = errors.New("connected-machine installation approval is pending")
	ErrInstallationDenied         = errors.New("connected-machine installation was denied")
	ErrInstallationExpired        = errors.New("connected-machine installation pairing expired")
	ErrInstallationUnavailable    = errors.New("connected-machine installation material is unavailable")
	ErrProvisioningUnavailable    = errors.New("connected-machine canonical helper provisioning is unavailable")
	ErrEnrollmentNotFound         = errors.New("connected-machine enrollment not found")
	ErrEnrollmentState            = errors.New("connected-machine enrollment state does not allow this operation")
	ErrIdempotencyKeyRequired     = errors.New("connected-machine enrollment idempotency key is required")
	ErrTerminalSessionNotFound    = errors.New("connected-machine terminal session not found")
	ErrTerminalSessionReserved    = errors.New("connected-machine default terminal session is reserved")
	ErrTerminalSessionLimit       = errors.New("connected-machine terminal session limit reached")
	ErrTerminalSessionConflict    = errors.New("connected-machine terminal session name conflict")
	ErrTerminalSessionInvalidName = errors.New("invalid connected-machine terminal session name")
	ErrTerminalSessionIdempotency = errors.New("terminal session idempotency key is required")
)

var terminalSessionNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

type SeatAuthorizer interface {
	ReserveConnectedMachineSeat(context.Context, *db.Tx, string) error
}

func (s *Service) ConsumeInstallation(ctx context.Context, verifier string) (json.RawMessage, error) {
	if strings.TrimSpace(verifier) == "" || strings.TrimSpace(s.encryptionKey) == "" {
		return nil, ErrInstallationUnavailable
	}
	hash := sha256.Sum256([]byte(verifier))
	var ciphertext []byte
	err := s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		value, err := tx.Queries().ConsumeConnectedMachineInstallationConfig(ctx, hash[:])
		if errors.Is(err, sql.ErrNoRows) {
			pairing, lookupErr := tx.Queries().GetConnectedMachinePairingForVerifier(ctx, hash[:])
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
	db                *db.DB
	audit             *audit.Writer
	policy            Policy
	seats             SeatAuthorizer
	now               func() time.Time
	provisioner       agentunnel.Client
	encryptionKey     string
	credentials       agentunnel.CredentialIssuer
	issuer            string
	ttl               time.Duration
	uploadMaxBytes    int64
	uploadMIMEs       []string
	uploadRetention   int64
	maxSessions       int
	controlSigner     *mint.Provider
	controlRuntime    connectedMachineHelperRuntime
	bootstrapCommand  string
	helperGrant       func(context.Context, string, string, string, time.Duration) (HelperEnrollmentGrant, error)
	helperArtifacts   map[string]HelperArtifact
	artifactPublicKey string
	helperBaseDomain  string
	helperListenPort  int32
}

type connectedMachineHelperRuntime interface {
	Terminal(context.Context, string, string, string, string, string) (helperruntime.Snapshot, error)
}

type HelperEnrollmentGrant struct {
	EnrollmentID string    `json:"enrollment_id"`
	HelperID     string    `json:"helper_id"`
	Credential   string    `json:"credential"`
	ExpiresAt    time.Time `json:"expires_at"`
}

func (s *Service) FailInstallation(ctx context.Context, enrollmentID, environmentID, helperID, helperEnrollmentID, stage string) error {
	if strings.TrimSpace(enrollmentID) == "" || strings.TrimSpace(environmentID) == "" || strings.TrimSpace(helperID) == "" || !slices.Contains([]string{"artifact_verification", "service_install", "service_readiness"}, stage) {
		return ErrEnrollmentState
	}
	n, err := s.db.Queries().FailConnectedMachineEnrollmentForHelper(ctx, dbsqlc.FailConnectedMachineEnrollmentForHelperParams{ID: enrollmentID, EnvironmentID: environmentID, HelperID: helperID, HelperEnrollmentID: helperEnrollmentID})
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrEnrollmentState
	}
	return s.audit.Write(ctx, audit.Event{ActorType: audit.ActorSystem, EventType: "connected_machine.installation_failed", ResourceType: "connected_machine_enrollment", ResourceID: enrollmentID, IdempotencyKey: "connected_machine.installation_failed:" + enrollmentID + ":" + stage, Metadata: map[string]any{"environment_id": environmentID, "helper_id": helperID, "stage": stage}})
}

type HelperArtifact struct {
	Schema       string `json:"schema"`
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
// depend on a synchronous Papercode response.
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
			_, _ = s.db.Queries().MarkStaleConnectedMachinesOffline(ctx, sql.NullTime{Time: s.now().UTC().Add(-s.policy.OfflineAfter), Valid: true})
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-ticker.C:
			}
		}
	}
}

func (s *Service) ConfigureProvisioning(provider agentunnel.Client, encryptionKey string) {
	s.provisioner, s.encryptionKey = provider, encryptionKey
}

func (s *Service) ConfigureAccess(credentials agentunnel.CredentialIssuer, issuer string, ttl time.Duration, uploadMaxBytes int64, uploadMIMEs []string, uploadRetention int64) {
	s.credentials, s.issuer, s.ttl, s.uploadMaxBytes, s.uploadMIMEs, s.uploadRetention = credentials, strings.TrimRight(issuer, "/"), ttl, uploadMaxBytes, slices.Clone(uploadMIMEs), uploadRetention
}

func (s *Service) ConfigureTerminalSessions(maxActive int, signer *mint.Provider, client *http.Client) {
	if maxActive > 0 {
		s.maxSessions = maxActive
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
		return errors.New("connected-machine helper route configuration is invalid")
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
	if err := decoder.Decode(&artifacts); err != nil || len(artifacts) == 0 || len(artifacts) > 8 || keyErr != nil || len(decodedPublicKey) != ed25519.PublicKeySize {
		return errors.New("connected-machine helper artifacts are invalid")
	}
	configured := make(map[string]HelperArtifact, len(artifacts))
	for _, artifact := range artifacts {
		key := artifact.Platform + "-" + artifact.Architecture
		parsedURL, urlErr := url.Parse(artifact.URL)
		digest, digestErr := hex.DecodeString(artifact.SHA256)
		signature, signatureErr := decodeArtifactBase64(artifact.Signature)
		payload, payloadErr := json.Marshal(struct {
			Architecture string `json:"architecture"`
			ByteLength   int64  `json:"byte_length"`
			Platform     string `json:"platform"`
			Schema       string `json:"schema"`
			SHA256       string `json:"sha256"`
			URL          string `json:"url"`
			Version      string `json:"version"`
		}{artifact.Architecture, artifact.ByteLength, artifact.Platform, artifact.Schema, artifact.SHA256, artifact.URL, artifact.Version})
		if artifact.Schema != "paperboat.helper-artifact/v1" || artifact.Version == "" || !slices.Contains([]string{"darwin", "linux"}, artifact.Platform) || !slices.Contains([]string{"amd64", "arm64"}, artifact.Architecture) || urlErr != nil || parsedURL.Scheme != "https" || parsedURL.User != nil || parsedURL.Hostname() == "" || parsedURL.RawQuery != "" || parsedURL.Fragment != "" || artifact.ByteLength < 1 || artifact.ByteLength > 256<<20 || digestErr != nil || len(digest) != sha256.Size || signatureErr != nil || len(signature) != ed25519.SignatureSize || payloadErr != nil || !ed25519.Verify(ed25519.PublicKey(decodedPublicKey), payload, signature) || configured[key].Schema != "" {
			return errors.New("connected-machine helper artifacts are invalid")
		}
		configured[key] = artifact
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
	return &Service{db: store, audit: auditWriter, policy: policy, seats: seats, now: time.Now, maxSessions: 32}
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
	ConnectedMachineID   string     `json:"connected_machine_id,omitempty"`
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
		return EnrollmentStart{}, errors.New("connected-machine enrollment encryption is not configured")
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
	row, err := s.db.Queries().CreateConnectedMachineEnrollment(ctx, dbsqlc.CreateConnectedMachineEnrollmentParams{
		ID: newID("cme"), UserID: userID, OperationID: newID("op_enroll"), IdempotencyKey: idempotencyKey,
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
	_ = s.audit.Write(ctx, audit.Event{ActorUserID: userID, ActorType: audit.ActorUser, EventType: "connected_machine.enrollment_started", ResourceType: "connected_machine_enrollment", ResourceID: row.ID, IdempotencyKey: "connected_machine.enrollment_started:" + row.ID, Metadata: map[string]any{"operation_id": row.OperationID, "generation": row.Generation}})
	return result, nil
}

func (s *Service) Enrollment(ctx context.Context, userID, enrollmentID string) (Enrollment, error) {
	_, _ = s.db.Queries().ExpireConnectedMachineEnrollment(ctx, dbsqlc.ExpireConnectedMachineEnrollmentParams{ID: strings.TrimSpace(enrollmentID), UserID: strings.TrimSpace(userID)})
	row, err := s.db.Queries().GetConnectedMachineEnrollmentForUser(ctx, dbsqlc.GetConnectedMachineEnrollmentForUserParams{ID: strings.TrimSpace(enrollmentID), UserID: strings.TrimSpace(userID)})
	if errors.Is(err, sql.ErrNoRows) {
		return Enrollment{}, ErrEnrollmentNotFound
	}
	if err != nil {
		return Enrollment{}, err
	}
	result := mapEnrollment(row)
	if row.PairingID.Valid {
		pairing, pairingErr := s.db.Queries().GetConnectedMachinePairingByID(ctx, row.PairingID.String)
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
	n, err := s.db.Queries().CancelConnectedMachineEnrollment(ctx, dbsqlc.CancelConnectedMachineEnrollmentParams{ID: strings.TrimSpace(enrollmentID), UserID: strings.TrimSpace(userID)})
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrEnrollmentState
	}
	return s.audit.Write(ctx, audit.Event{ActorUserID: userID, ActorType: audit.ActorUser, EventType: "connected_machine.enrollment_cancelled", ResourceType: "connected_machine_enrollment", ResourceID: enrollmentID, IdempotencyKey: "connected_machine.enrollment_cancelled:" + enrollmentID})
}

func (s *Service) RetryEnrollment(ctx context.Context, userID, enrollmentID string) (EnrollmentStart, error) {
	if strings.TrimSpace(s.encryptionKey) == "" {
		return EnrollmentStart{}, errors.New("connected-machine enrollment encryption is not configured")
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
	row, err := s.db.Queries().RetryConnectedMachineEnrollment(ctx, dbsqlc.RetryConnectedMachineEnrollmentParams{BootstrapTokenHash: hash[:], BootstrapTokenCiphertext: ciphertext, ExpiresAt: s.now().UTC().Add(s.policy.PairingLifetime), ID: strings.TrimSpace(enrollmentID), UserID: strings.TrimSpace(userID)})
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

func mapEnrollment(row dbsqlc.ConnectedMachineEnrollment) Enrollment {
	result := Enrollment{ID: row.ID, OperationID: row.OperationID, State: row.State, Generation: row.Generation, PairingID: row.PairingID.String, ConnectedMachineID: row.ConnectedMachineID.String, RequestedDisplayName: row.RequestedDisplayName.String, Platform: row.Platform.String, Architecture: row.Architecture.String, WorkspaceRoot: row.WorkspaceRoot.String, ExpiresAt: row.ExpiresAt, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt}
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
	params := dbsqlc.CreateConnectedMachinePairingParams{ID: newID("cmp"), VerifierHash: verifierHash[:], UserCode: code, RequestedDisplayName: strings.TrimSpace(in.DisplayName), Platform: strings.ToLower(strings.TrimSpace(in.Platform)), Architecture: strings.ToLower(strings.TrimSpace(in.Architecture)), WorkspaceRoot: filepath.Clean(in.WorkspaceRoot), RuntimeVersions: in.RuntimeVersions, ExpiresAt: expires}
	var row dbsqlc.ConnectedMachinePairing
	if strings.TrimSpace(in.EnrollmentToken) == "" {
		row, err = s.db.Queries().CreateConnectedMachinePairing(ctx, params)
	} else {
		tokenHash := sha256.Sum256([]byte(strings.TrimSpace(in.EnrollmentToken)))
		err = s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
			enrollment, err := tx.Queries().GetConnectedMachineEnrollmentForTokenUpdate(ctx, tokenHash[:])
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
			row, err = tx.Queries().CreateConnectedMachinePairing(ctx, params)
			if err != nil {
				return err
			}
			n, err := tx.Queries().ClaimConnectedMachineEnrollment(ctx, dbsqlc.ClaimConnectedMachineEnrollmentParams{PairingID: sql.NullString{String: row.ID, Valid: true}, RequestedDisplayName: sql.NullString{String: params.RequestedDisplayName, Valid: true}, Platform: sql.NullString{String: params.Platform, Valid: true}, Architecture: sql.NullString{String: params.Architecture, Valid: true}, WorkspaceRoot: sql.NullString{String: params.WorkspaceRoot, Valid: true}, ID: enrollment.ID})
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

type Machine struct {
	ID              string          `json:"id"`
	EnvironmentID   string          `json:"environment_id"`
	DisplayName     string          `json:"display_name"`
	Platform        string          `json:"platform"`
	Architecture    string          `json:"architecture"`
	WorkspaceRoot   string          `json:"workspace_root"`
	State           string          `json:"state"`
	SeatState       string          `json:"seat_state"`
	Online          bool            `json:"online"`
	RuntimeVersions json.RawMessage `json:"runtime_versions"`
	EnrolledAt      *time.Time      `json:"enrolled_at,omitempty"`
	LastSeenAt      *time.Time      `json:"last_seen_at,omitempty"`
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
	entitlement, err := s.db.Queries().GetConnectedMachineEntitlement(ctx, userID)
	if errors.Is(err, sql.ErrNoRows) {
		return Overview{EntitlementState: "unavailable"}, nil
	}
	if err != nil {
		return Overview{}, err
	}
	occupied, err := s.db.Queries().CountOccupiedConnectedMachineSeats(ctx, userID)
	if err != nil {
		return Overview{}, err
	}
	usage, err := s.db.Queries().GetConnectedMachineBandwidthUsage(ctx, userID)
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
	ID            string     `json:"id"`
	Name          string     `json:"name"`
	IsDefault     bool       `json:"is_default"`
	State         string     `json:"state"`
	AttachedCount *int       `json:"attached_count,omitempty"`
	LastActiveAt  *time.Time `json:"last_active_at,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

// BandwidthReservation is a trusted capacity grant. A data-plane relay must
// forward no more than GrantedBytes before requesting another grant.
type BandwidthReservation struct {
	GrantedBytes int64 `json:"granted_bytes"`
	Exhausted    bool  `json:"exhausted"`
}

type ConnectResponse struct {
	Schema                string         `json:"schema,omitempty"`
	Capabilities          []string       `json:"capabilities,omitempty"`
	Issuer                string         `json:"issuer,omitempty"`
	ConnectedMachineID    string         `json:"connected_machine_id"`
	ConnectedMachineState string         `json:"connected_machine_state"`
	Connectable           bool           `json:"connectable"`
	ExpiresAt             time.Time      `json:"expires_at"`
	Environment           map[string]any `json:"environment,omitempty"`
	Terminal              map[string]any `json:"terminal,omitempty"`
	Upload                map[string]any `json:"upload,omitempty"`
	Status                string         `json:"status,omitempty"`
	Reason                string         `json:"reason,omitempty"`
	RetryAfterSeconds     int            `json:"retry_after_seconds,omitempty"`
}

func (r ConnectResponse) MarshalJSON() ([]byte, error) {
	if r.Schema != accessdescriptor.SchemaV1 {
		type legacy ConnectResponse
		return json.Marshal(legacy(r))
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
	if r.Upload != nil && r.Upload["auth"] != nil {
		upload, err := decodeCanonical[accessdescriptor.Upload](r.Upload)
		if err != nil {
			return nil, err
		}
		out.Upload = &upload
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

func setCanonicalMachineIdentity(response *ConnectResponse, row dbsqlc.ConnectedMachine) {
	response.Schema = accessdescriptor.SchemaV1
	response.Capabilities = []string{accessdescriptor.CapabilityTerminal, accessdescriptor.CapabilityHerdr, accessdescriptor.CapabilityUpload, accessdescriptor.CapabilityPreview, accessdescriptor.CapabilityActivity}
	response.Environment = map[string]any{"id": row.EnvironmentID, "kind": accessdescriptor.EnvironmentBYOD, "resource_id": row.ID, "display_name": row.DisplayName, "state": machineConnectionState(response.Connectable, row.State), "root": row.WorkspaceRoot}
}

func (s *Service) Connect(ctx context.Context, userID, machineID, clientSessionID string) (ConnectResponse, error) {
	return s.ConnectTerminalSession(ctx, userID, machineID, clientSessionID, "")
}

func (s *Service) ConnectTerminalSession(ctx context.Context, userID, machineID, clientSessionID, terminalSessionID string) (ConnectResponse, error) {
	row, err := s.db.Queries().GetConnectedMachineForUser(ctx, dbsqlc.GetConnectedMachineForUserParams{ID: machineID, UserID: userID})
	if errors.Is(err, sql.ErrNoRows) {
		return ConnectResponse{}, ErrNotFound
	}
	if err != nil {
		return ConnectResponse{}, err
	}
	terminalSession, err := s.terminalSession(ctx, userID, machineID, terminalSessionID)
	if err != nil {
		return ConnectResponse{}, err
	}
	ttl := s.ttl
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	if s.controlSigner != nil && ttl > 5*time.Minute {
		ttl = 5 * time.Minute
	}
	expires := s.now().UTC().Add(ttl)
	response := ConnectResponse{Issuer: s.issuer, ConnectedMachineID: row.ID, ConnectedMachineState: row.State, ExpiresAt: expires, Status: "connector_connecting", Reason: "connector_offline", RetryAfterSeconds: 2}
	setCanonicalMachineIdentity(&response, row)
	if row.State == "revoked" || row.State == "disconnected" || row.State == "deleted" || row.SeatState != "occupied" {
		response.Status = "connected_machine_revoked"
		response.Reason = "access_revoked"
		return response, nil
	}
	route, routeErr := s.db.Queries().GetActiveHelperRouteForEnvironment(ctx, row.EnvironmentID)
	if errors.Is(routeErr, sql.ErrNoRows) {
		return response, nil
	}
	if routeErr != nil {
		return ConnectResponse{}, routeErr
	}
	httpBaseURL, websocketBaseURL := "https://"+route.PublicHost, "wss://"+route.PublicHost
	if clientSessionID == "" || s.controlSigner == nil && s.credentials == nil {
		return ConnectResponse{}, errors.New("connected-machine credential issuer is unavailable")
	}
	input := agentunnel.CredentialInput{UserID: userID, ProjectID: row.ID, EnvironmentID: row.EnvironmentID, ClientSessionID: clientSessionID, HTTPBaseURL: httpBaseURL, ExpiresAt: expires}
	if s.controlSigner == nil {
		if err := s.credentials.CheckCLI(ctx, input); err != nil {
			return ConnectResponse{}, err
		}
		if checker, ok := s.credentials.(interface {
			CheckHealth(context.Context, agentunnel.CredentialInput) error
		}); ok {
			if err := checker.CheckHealth(ctx, input); err != nil {
				response.Status = "connector_connecting"
				response.Reason = "helper_unhealthy"
				return response, nil
			}
		}
	}
	if err := s.applyTerminalSessionOperationsForSession(ctx, row.ID, terminalSession.ID); err != nil {
		response.Status = "papercode_starting"
		response.Reason = "terminal_session_operation_pending"
		return response, nil
	}
	credentials, err := s.issueConnectedMachineCredentials(ctx, input, terminalSession.ID)
	if err != nil {
		return ConnectResponse{}, err
	}
	if len(compactSessionIDs(credentials.TerminalSessionID, credentials.FileSessionID)) == 0 {
		return ConnectResponse{}, errors.New("connected-machine credential issuer returned no revocable sessions")
	}
	if err := s.db.Queries().CreateConnectedMachineAccessSession(ctx, dbsqlc.CreateConnectedMachineAccessSessionParams{
		ID: newID("cmas"), ConnectedMachineID: row.ID, UserID: userID, EnvironmentID: row.EnvironmentID,
		ClientSessionID: clientSessionID, HttpBaseUrl: httpBaseURL,
		PapercodeTerminalSessionID: credentials.TerminalSessionID, PapercodeFileSessionID: credentials.FileSessionID,
		ExpiresAt: expires,
	}); err != nil {
		cleanupErr := s.revokeCredentialSessions(ctx, machineAccessSession{
			UserID: userID, ConnectedMachineID: row.ID, EnvironmentID: row.EnvironmentID,
			ClientSessionID: clientSessionID, HTTPBaseURL: httpBaseURL,
			TerminalSessionID: credentials.TerminalSessionID, FileSessionID: credentials.FileSessionID,
		}, "access_session_persistence_failed")
		return ConnectResponse{}, errors.Join(err, cleanupErr)
	}
	response.Connectable, response.Status, response.Reason, response.RetryAfterSeconds = true, "ready", "ready", 0
	setCanonicalMachineIdentity(&response, row)
	response.Terminal = map[string]any{"endpoint": websocketBaseURL + "/v1/runtime", "session_id": terminalSession.ID, "thread_id": terminalSession.ThreadID, "terminal_id": terminalSession.TerminalID, "cwd": terminalSession.LaunchCwd, "auth": credentials.TerminalAuth}
	response.Upload = map[string]any{"endpoint": httpBaseURL + "/v1/uploads", "max_bytes": s.uploadMaxBytes, "allowed_mime_types": s.uploadMIMEs, "retention_seconds": s.uploadRetention, "auth": credentials.UploadAuth}
	return response, nil
}

func (s *Service) issueConnectedMachineCredentials(ctx context.Context, input agentunnel.CredentialInput, terminalSessionID string) (agentunnel.CLICredentials, error) {
	if s.controlSigner == nil {
		return s.credentials.IssueCLI(ctx, input)
	}
	issuedAt := s.now().UTC()
	terminalJTI, uploadJTI := newID("jti_helper_terminal"), newID("jti_helper_upload")
	sign := func(class string, scopes []string, jti string) (string, error) {
		return s.controlSigner.SignCredential(mint.CredentialInput{
			Issuer: s.issuer, Audience: "paperboat-helper", Subject: input.UserID, JTI: jti,
			IssuedAt: issuedAt, ExpiresAt: input.ExpiresAt, CredentialClass: class, Scopes: scopes,
			EnvironmentID: input.EnvironmentID, UserID: input.UserID, ClientSessionID: input.ClientSessionID, SessionID: terminalSessionID,
		})
	}
	terminalToken, err := sign("terminal_operation", []string{"terminal:operate"}, terminalJTI)
	if err != nil {
		return agentunnel.CLICredentials{}, err
	}
	uploadToken, err := sign("image_stage", []string{"file:stage"}, uploadJTI)
	if err != nil {
		return agentunnel.CLICredentials{}, err
	}
	return agentunnel.CLICredentials{
		TerminalAuth:      map[string]any{"method": "bearer", "token": terminalToken, "expires_at": input.ExpiresAt, "scopes": []string{"terminal:operate"}},
		UploadAuth:        map[string]any{"method": "bearer", "token": uploadToken, "expires_at": input.ExpiresAt, "scopes": []string{"file:stage"}},
		TerminalSessionID: terminalJTI, FileSessionID: uploadJTI,
	}, nil
}

func (s *Service) ConnectionStatus(ctx context.Context, userID, machineID string) (ConnectResponse, error) {
	return s.ConnectionStatusForTerminalSession(ctx, userID, machineID, "")
}

func (s *Service) ConnectionStatusForTerminalSession(ctx context.Context, userID, machineID, terminalSessionID string) (ConnectResponse, error) {
	row, err := s.db.Queries().GetConnectedMachineForUser(ctx, dbsqlc.GetConnectedMachineForUserParams{ID: machineID, UserID: userID})
	if errors.Is(err, sql.ErrNoRows) {
		return ConnectResponse{}, ErrNotFound
	}
	if err != nil {
		return ConnectResponse{}, err
	}
	if _, err := s.terminalSession(ctx, userID, machineID, terminalSessionID); err != nil {
		return ConnectResponse{}, err
	}
	response := ConnectResponse{Issuer: s.issuer, ConnectedMachineID: row.ID, ConnectedMachineState: row.State, ExpiresAt: s.now().UTC(), Status: "connector_connecting", Reason: "connector_offline", RetryAfterSeconds: 2}
	setCanonicalMachineIdentity(&response, row)
	if row.State == "revoked" || row.State == "disconnected" || row.State == "deleted" || row.SeatState != "occupied" {
		response.Status = "connected_machine_revoked"
		response.Reason = "access_revoked"
		return response, nil
	}
	if _, err := s.db.Queries().GetActiveHelperRouteForEnvironment(ctx, row.EnvironmentID); errors.Is(err, sql.ErrNoRows) {
		return response, nil
	} else if err != nil {
		return ConnectResponse{}, err
	}
	response.Connectable, response.Status, response.Reason, response.RetryAfterSeconds = true, "ready", "ready", 0
	setCanonicalMachineIdentity(&response, row)
	return response, nil
}

func (s *Service) terminalSession(ctx context.Context, userID, machineID, sessionID string) (dbsqlc.ConnectedMachineTerminalSession, error) {
	var (
		row dbsqlc.ConnectedMachineTerminalSession
		err error
	)
	if strings.TrimSpace(sessionID) == "" {
		row, err = s.db.Queries().GetDefaultConnectedMachineTerminalSession(ctx, dbsqlc.GetDefaultConnectedMachineTerminalSessionParams{ConnectedMachineID: machineID, UserID: userID})
	} else {
		row, err = s.db.Queries().GetConnectedMachineTerminalSession(ctx, dbsqlc.GetConnectedMachineTerminalSessionParams{ID: sessionID, ConnectedMachineID: machineID, UserID: userID})
	}
	if errors.Is(err, sql.ErrNoRows) {
		return dbsqlc.ConnectedMachineTerminalSession{}, ErrTerminalSessionNotFound
	}
	return row, err
}

func (s *Service) Approve(ctx context.Context, userID, userCode string) (Machine, error) {
	var out Machine
	var pairingID string
	var alreadyProvisioned bool
	var pairingExpired bool
	err := s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		pairing, err := tx.Queries().GetConnectedMachinePairingForCode(ctx, strings.TrimSpace(userCode))
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if pairing.State == "approved" && pairing.ApprovedByUserID.Valid && pairing.ApprovedByUserID.String == userID && pairing.ConnectedMachineID.Valid {
			row, err := tx.Queries().GetConnectedMachineForUser(ctx, dbsqlc.GetConnectedMachineForUserParams{ID: pairing.ConnectedMachineID.String, UserID: userID})
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
			if _, err := tx.Queries().ExpireConnectedMachinePairing(ctx, pairing.ID); err != nil {
				return err
			}
			if enrollment, err := tx.Queries().GetConnectedMachineEnrollmentForPairingUpdate(ctx, sql.NullString{String: pairing.ID, Valid: true}); err == nil {
				if _, err := tx.Queries().ExpireConnectedMachineEnrollment(ctx, dbsqlc.ExpireConnectedMachineEnrollmentParams{ID: enrollment.ID, UserID: userID}); err != nil {
					return err
				}
			} else if !errors.Is(err, sql.ErrNoRows) {
				return err
			}
			pairingExpired = true
			return nil
		}
		enrollment, enrollmentErr := tx.Queries().GetConnectedMachineEnrollmentForPairingUpdate(ctx, sql.NullString{String: pairing.ID, Valid: true})
		if enrollmentErr == nil {
			if enrollment.UserID != userID || enrollment.State != "awaiting_approval" {
				return ErrNotFound
			}
		} else if !errors.Is(enrollmentErr, sql.ErrNoRows) {
			return enrollmentErr
		}
		if enrollmentErr == nil && enrollment.ConnectedMachineID.Valid {
			row, err := tx.Queries().GetConnectedMachineForUser(ctx, dbsqlc.GetConnectedMachineForUserParams{ID: enrollment.ConnectedMachineID.String, UserID: userID})
			if err != nil || row.State == "revoked" || row.State == "deleted" || row.Platform != pairing.Platform || row.Architecture != pairing.Architecture || row.WorkspaceRoot != pairing.WorkspaceRoot || row.DisplayName != pairing.RequestedDisplayName {
				return ErrEnrollmentState
			}
			if n, err := tx.Queries().ApproveConnectedMachinePairing(ctx, dbsqlc.ApproveConnectedMachinePairingParams{UserID: sql.NullString{String: userID, Valid: true}, ConnectedMachineID: sql.NullString{String: row.ID, Valid: true}, ID: pairing.ID}); err != nil || n != 1 {
				if err != nil {
					return err
				}
				return ErrPairingUsed
			}
			if n, err := tx.Queries().ApproveConnectedMachineEnrollment(ctx, dbsqlc.ApproveConnectedMachineEnrollmentParams{ConnectedMachineID: sql.NullString{String: row.ID, Valid: true}, PairingID: sql.NullString{String: pairing.ID, Valid: true}, UserID: userID}); err != nil || n != 1 {
				if err != nil {
					return err
				}
				return ErrEnrollmentState
			}
			if err := s.ensureHelperRoute(ctx, tx, row.ID, row.EnvironmentID); err != nil {
				return err
			}
			out, pairingID = mapMachine(row), pairing.ID
			return s.audit.WriteTx(ctx, tx, audit.Event{ActorUserID: userID, ActorType: audit.ActorUser, EventType: "connected_machine.installation_retried", ResourceType: "connected_machine", ResourceID: row.ID, IdempotencyKey: "connected_machine.installation_retried:" + pairing.ID, Metadata: map[string]any{"environment_id": row.EnvironmentID, "generation": enrollment.Generation}})
		}
		if s.seats == nil {
			return ErrSeatUnavailable
		}
		if err := s.seats.ReserveConnectedMachineSeat(ctx, tx, userID); err != nil {
			return err
		}
		row, err := tx.Queries().CreateConnectedMachine(ctx, dbsqlc.CreateConnectedMachineParams{ID: newID("cm"), UserID: userID, EnvironmentID: newID("env"), DisplayName: pairing.RequestedDisplayName, Platform: pairing.Platform, Architecture: pairing.Architecture, WorkspaceRoot: pairing.WorkspaceRoot, RuntimeVersions: pairing.RuntimeVersions})
		if err != nil {
			return err
		}
		if _, err := tx.Queries().CreateControlEnvironment(ctx, dbsqlc.CreateControlEnvironmentParams{ID: row.EnvironmentID, WorkspaceID: row.ID, OwnerUserID: sql.NullString{String: userID, Valid: true}, DesiredState: "active"}); err != nil {
			return err
		}
		if err := s.ensureHelperRoute(ctx, tx, row.ID, row.EnvironmentID); err != nil {
			return err
		}
		if err := tx.Queries().CreateDefaultConnectedMachineTerminalSession(ctx, dbsqlc.CreateDefaultConnectedMachineTerminalSessionParams{ID: "cmts_default_" + row.ID, ConnectedMachineID: row.ID, LaunchCwd: row.WorkspaceRoot}); err != nil {
			return err
		}
		if _, err := s.ensureCurrentBandwidthPeriod(ctx, tx, row); err != nil {
			return err
		}
		if n, err := tx.Queries().ApproveConnectedMachinePairing(ctx, dbsqlc.ApproveConnectedMachinePairingParams{UserID: sql.NullString{String: userID, Valid: true}, ConnectedMachineID: sql.NullString{String: row.ID, Valid: true}, ID: pairing.ID}); err != nil || n != 1 {
			if err != nil {
				return err
			}
			return ErrPairingUsed
		}
		if enrollmentErr == nil {
			n, err := tx.Queries().ApproveConnectedMachineEnrollment(ctx, dbsqlc.ApproveConnectedMachineEnrollmentParams{ConnectedMachineID: sql.NullString{String: row.ID, Valid: true}, PairingID: sql.NullString{String: pairing.ID, Valid: true}, UserID: userID})
			if err != nil {
				return err
			}
			if n != 1 {
				return ErrEnrollmentState
			}
		}
		out = mapMachine(row)
		pairingID = pairing.ID
		return s.audit.WriteTx(ctx, tx, audit.Event{ActorUserID: userID, ActorType: audit.ActorUser, EventType: "connected_machine.approved", ResourceType: "connected_machine", ResourceID: row.ID, IdempotencyKey: "connected_machine.approved:" + pairing.ID, Metadata: map[string]any{"platform": row.Platform, "architecture": row.Architecture}})
	})
	if pairingExpired {
		return Machine{}, ErrPairingExpired
	}
	if err != nil || alreadyProvisioned {
		return out, err
	}
	if s.helperGrant == nil {
		return Machine{}, ErrProvisioningUnavailable
	}
	if err := s.provisionApprovedMachine(ctx, userID, pairingID, out); err != nil {
		return Machine{}, err
	}
	return out, nil
}

func (s *Service) ensureHelperRoute(ctx context.Context, tx *db.Tx, machineID, environmentID string) error {
	if s.helperBaseDomain == "" || s.helperListenPort == 0 {
		return ErrProvisioningUnavailable
	}
	if _, err := tx.Queries().GetHelperRouteForEnvironment(ctx, environmentID); err == nil {
		return nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	publicHost := strings.ReplaceAll(strings.ToLower(machineID), "_", "-") + "." + s.helperBaseDomain
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
		pairing, err := tx.Queries().GetConnectedMachinePairingForCode(ctx, userCode)
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
			if _, err := tx.Queries().ExpireConnectedMachinePairing(ctx, pairing.ID); err != nil {
				return err
			}
			if enrollment, err := tx.Queries().GetConnectedMachineEnrollmentForPairingUpdate(ctx, sql.NullString{String: pairing.ID, Valid: true}); err == nil {
				if _, err := tx.Queries().ExpireConnectedMachineEnrollment(ctx, dbsqlc.ExpireConnectedMachineEnrollmentParams{ID: enrollment.ID, UserID: userID}); err != nil {
					return err
				}
			} else if !errors.Is(err, sql.ErrNoRows) {
				return err
			}
			pairingExpired = true
			return nil
		}
		enrollment, err := tx.Queries().GetConnectedMachineEnrollmentForPairingUpdate(ctx, sql.NullString{String: pairing.ID, Valid: true})
		if errors.Is(err, sql.ErrNoRows) || err == nil && (enrollment.UserID != userID || enrollment.State != "awaiting_approval") {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if n, err := tx.Queries().DenyConnectedMachinePairing(ctx, dbsqlc.DenyConnectedMachinePairingParams{UserID: sql.NullString{String: userID, Valid: true}, ID: pairing.ID}); err != nil || n != 1 {
			if err != nil {
				return err
			}
			return ErrPairingUsed
		}
		if n, err := tx.Queries().DenyConnectedMachineEnrollment(ctx, dbsqlc.DenyConnectedMachineEnrollmentParams{PairingID: sql.NullString{String: pairing.ID, Valid: true}, UserID: userID}); err != nil || n != 1 {
			if err != nil {
				return err
			}
			return ErrEnrollmentState
		}
		return s.audit.WriteTx(ctx, tx, audit.Event{ActorUserID: userID, ActorType: audit.ActorUser, EventType: "connected_machine.denied", ResourceType: "connected_machine_enrollment", ResourceID: enrollment.ID, IdempotencyKey: "connected_machine.denied:" + pairing.ID})
	})
	if pairingExpired && err == nil {
		return ErrPairingExpired
	}
	return err
}

func (s *Service) provisionApprovedMachine(ctx context.Context, userID, pairingID string, machine Machine) error {
	if strings.TrimSpace(s.encryptionKey) == "" {
		return errors.New("connected-machine provisioning encryption is not configured")
	}
	if s.helperGrant == nil {
		return ErrProvisioningUnavailable
	}
	artifact, ok := s.helperArtifacts[machine.Platform+"-"+machine.Architecture]
	if !ok || s.artifactPublicKey == "" {
		return errors.New("connected-machine helper artifact is unavailable")
	}
	enrollment, err := s.db.Queries().GetConnectedMachineEnrollmentForPairingUpdate(ctx, sql.NullString{String: pairingID, Valid: true})
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
		"schema": "paperboat.byod-installation/v1", "machine_id": machine.ID, "machine_enrollment_id": enrollment.ID, "environment_id": machine.EnvironmentID,
		"control_url": s.issuer, "helper_id": grant.HelperID, "enrollment_id": grant.EnrollmentID,
		"enrollment_credential": grant.Credential, "reuse_identity": reuseIdentity, "expires_at": grant.ExpiresAt,
		"artifact": artifact, "artifact_public_key": s.artifactPublicKey,
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
		n, err := tx.Queries().SetConnectedMachineInstallationConfig(ctx, dbsqlc.SetConnectedMachineInstallationConfigParams{ID: pairingID, Ciphertext: ciphertext})
		if err != nil {
			return err
		}
		if n != 1 {
			return ErrPairingUsed
		}
		_, err = tx.Queries().MarkConnectedMachineEnrollmentMaterialIssued(ctx, sql.NullString{String: pairingID, Valid: true})
		return err
	})
}

// ReserveBandwidth atomically grants capacity from the machine's included
// period allowance and then the owner's paid top-ups. It intentionally grants
// a partial amount when the requested window crosses exhaustion; the caller
// must stop forwarding once that grant is consumed.
func (s *Service) ReserveBandwidth(ctx context.Context, machineID string, requestedBytes int64) (BandwidthReservation, error) {
	if strings.TrimSpace(machineID) == "" {
		return BandwidthReservation{}, ErrNotFound
	}
	if requestedBytes <= 0 {
		return BandwidthReservation{}, ErrInvalidBandwidth
	}
	var reservation BandwidthReservation
	err := s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		machine, err := tx.Queries().GetConnectedMachineForBandwidthUpdate(ctx, strings.TrimSpace(machineID))
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		reservation, err = s.reserveBandwidthForMachineTx(ctx, tx, machine, requestedBytes, s.now().UTC())
		return err
	})
	return reservation, err
}

// DebitEnvironmentBandwidthTx reconciles trusted edge usage against a BYOD
// environment inside the caller's transaction. Hosted environments return a
// zero, non-exhausted result because they do not use the BYOD entitlement.
func (s *Service) DebitEnvironmentBandwidthTx(ctx context.Context, tx *db.Tx, environmentID string, bytes int64, now time.Time) (int64, bool, error) {
	if tx == nil || strings.TrimSpace(environmentID) == "" || bytes <= 0 {
		return 0, false, ErrInvalidBandwidth
	}
	machine, err := tx.Queries().GetConnectedMachineForEnvironmentBandwidthUpdate(ctx, strings.TrimSpace(environmentID))
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	reservation, err := s.reserveBandwidthForMachineTx(ctx, tx, machine, bytes, now.UTC())
	return reservation.GrantedBytes, reservation.Exhausted, err
}

func (s *Service) reserveBandwidthForMachineTx(ctx context.Context, tx *db.Tx, machine dbsqlc.ConnectedMachine, requestedBytes int64, now time.Time) (BandwidthReservation, error) {
	if machine.State != "online" || machine.SeatState != "occupied" {
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
		rows, err := tx.Queries().ConsumeConnectedMachineIncludedBandwidth(ctx, dbsqlc.ConsumeConnectedMachineIncludedBandwidthParams{ID: period.ID, Bytes: consume})
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
		topups, err := tx.Queries().ListActiveConnectedMachineTopupsForUpdate(ctx, machine.UserID)
		if err != nil {
			return BandwidthReservation{}, err
		}
		for _, topup := range topups {
			if remaining == 0 {
				break
			}
			consume := minInt64(remaining, topup.RemainingBytes)
			rows, err := tx.Queries().ConsumeConnectedMachineTopup(ctx, dbsqlc.ConsumeConnectedMachineTopupParams{ID: topup.ID, Bytes: consume})
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
		rows, err := tx.Queries().RecordConnectedMachineTopupConsumption(ctx, dbsqlc.RecordConnectedMachineTopupConsumptionParams{ID: period.ID, Bytes: topupBytes})
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

func (s *Service) ensureCurrentBandwidthPeriod(ctx context.Context, tx *db.Tx, machine dbsqlc.ConnectedMachine) (dbsqlc.ConnectedMachineBandwidthPeriod, error) {
	return s.ensureCurrentBandwidthPeriodAt(ctx, tx, machine, s.now().UTC())
}

func (s *Service) ensureCurrentBandwidthPeriodAt(ctx context.Context, tx *db.Tx, machine dbsqlc.ConnectedMachine, now time.Time) (dbsqlc.ConnectedMachineBandwidthPeriod, error) {
	entitlement, err := tx.Queries().GetConnectedMachineEntitlementForUpdate(ctx, machine.UserID)
	if errors.Is(err, sql.ErrNoRows) {
		return dbsqlc.ConnectedMachineBandwidthPeriod{}, ErrBandwidthDenied
	}
	if err != nil {
		return dbsqlc.ConnectedMachineBandwidthPeriod{}, err
	}
	if (entitlement.State != "active" && entitlement.State != "trialing") || !now.Before(entitlement.CurrentPeriodEnd) || now.Before(entitlement.CurrentPeriodStart) {
		return dbsqlc.ConnectedMachineBandwidthPeriod{}, ErrBandwidthDenied
	}
	return tx.Queries().UpsertConnectedMachineBandwidthPeriod(ctx, dbsqlc.UpsertConnectedMachineBandwidthPeriodParams{ID: newID("cmbp"), ConnectedMachineID: machine.ID, PeriodStart: entitlement.CurrentPeriodStart, PeriodEnd: entitlement.CurrentPeriodEnd, IncludedBytes: entitlement.AllowanceBytes})
}

func minInt64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func (s *Service) List(ctx context.Context, userID string, limit, offset int) ([]Machine, int, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	rows, err := s.db.Queries().ListConnectedMachinesForUser(ctx, dbsqlc.ListConnectedMachinesForUserParams{UserID: userID, PageLimit: int32(limit), PageOffset: int32(offset)})
	if err != nil {
		return nil, 0, err
	}
	total, err := s.db.Queries().CountConnectedMachinesForUser(ctx, userID)
	if err != nil {
		return nil, 0, err
	}
	out := make([]Machine, 0, len(rows))
	for _, row := range rows {
		out = append(out, mapMachine(row))
	}
	return out, int(total), nil
}

func (s *Service) Get(ctx context.Context, userID, machineID string) (Machine, error) {
	row, err := s.db.Queries().GetConnectedMachineForUser(ctx, dbsqlc.GetConnectedMachineForUserParams{ID: machineID, UserID: userID})
	if errors.Is(err, sql.ErrNoRows) {
		return Machine{}, ErrNotFound
	}
	if err != nil {
		return Machine{}, err
	}
	return mapMachine(row), nil
}

func (s *Service) ListTerminalSessions(ctx context.Context, userID, machineID string) ([]TerminalSession, error) {
	if _, err := s.Get(ctx, userID, machineID); err != nil {
		return nil, err
	}
	rows, err := s.db.Queries().ListConnectedMachineTerminalSessions(ctx, dbsqlc.ListConnectedMachineTerminalSessionsParams{ConnectedMachineID: machineID, UserID: userID})
	if err != nil {
		return nil, err
	}
	out := make([]TerminalSession, 0, len(rows))
	for _, row := range rows {
		out = append(out, mapTerminalSession(row))
	}
	return out, nil
}

func (s *Service) CreateTerminalSession(ctx context.Context, userID, machineID, name, idempotencyKey string, maxActive int) (TerminalSession, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	if !terminalSessionNamePattern.MatchString(name) || name == "default" {
		return TerminalSession{}, ErrTerminalSessionInvalidName
	}
	if strings.TrimSpace(idempotencyKey) == "" {
		return TerminalSession{}, ErrTerminalSessionIdempotency
	}
	if maxActive <= 0 {
		return TerminalSession{}, ErrTerminalSessionLimit
	}
	if existing, err := s.db.Queries().GetConnectedMachineTerminalSessionByIdempotencyKey(ctx, dbsqlc.GetConnectedMachineTerminalSessionByIdempotencyKeyParams{ConnectedMachineID: machineID, UserID: userID, IdempotencyKey: sql.NullString{String: idempotencyKey, Valid: true}}); err == nil {
		return mapTerminalSession(existing), nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return TerminalSession{}, err
	}
	machine, err := s.db.Queries().GetConnectedMachineForUser(ctx, dbsqlc.GetConnectedMachineForUserParams{ID: machineID, UserID: userID})
	if errors.Is(err, sql.ErrNoRows) {
		return TerminalSession{}, ErrNotFound
	}
	if err != nil {
		return TerminalSession{}, err
	}
	id, terminalID := newID("cmts"), newID("term")
	err = s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		if _, err := tx.Queries().LockConnectedMachineTerminalSessions(ctx, dbsqlc.LockConnectedMachineTerminalSessionsParams{ConnectedMachineID: machineID, UserID: userID}); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		if existing, err := tx.Queries().GetConnectedMachineTerminalSessionByIdempotencyKey(ctx, dbsqlc.GetConnectedMachineTerminalSessionByIdempotencyKeyParams{ConnectedMachineID: machineID, UserID: userID, IdempotencyKey: sql.NullString{String: idempotencyKey, Valid: true}}); err == nil {
			id, terminalID = existing.ID, existing.TerminalID
			return nil
		} else if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		count, err := tx.Queries().CountActiveConnectedMachineTerminalSessions(ctx, machineID)
		if err != nil {
			return err
		}
		if int(count) >= maxActive {
			return ErrTerminalSessionLimit
		}
		ordinal, err := tx.Queries().NextConnectedMachineTerminalSessionOrdinal(ctx, machineID)
		if err != nil {
			return err
		}
		return tx.Queries().CreateConnectedMachineTerminalSession(ctx, dbsqlc.CreateConnectedMachineTerminalSessionParams{ID: id, ConnectedMachineID: machineID, TerminalID: terminalID, Name: name, AutoNameOrdinal: ordinal, IdempotencyKey: sql.NullString{String: idempotencyKey, Valid: true}, LaunchCwd: machine.WorkspaceRoot})
	})
	if err != nil {
		return TerminalSession{}, err
	}
	row, err := s.db.Queries().GetConnectedMachineTerminalSession(ctx, dbsqlc.GetConnectedMachineTerminalSessionParams{ID: id, ConnectedMachineID: machineID, UserID: userID})
	if err != nil {
		return TerminalSession{}, err
	}
	return mapTerminalSession(row), nil
}

func (s *Service) CreateConfiguredTerminalSession(ctx context.Context, userID, machineID, name, idempotencyKey string) (TerminalSession, error) {
	return s.CreateTerminalSession(ctx, userID, machineID, name, idempotencyKey, s.maxSessions)
}

func (s *Service) RenameTerminalSession(ctx context.Context, userID, machineID, id, name string) (TerminalSession, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	if !terminalSessionNamePattern.MatchString(name) || name == "default" {
		return TerminalSession{}, ErrTerminalSessionInvalidName
	}
	n, err := s.db.Queries().RenameConnectedMachineTerminalSession(ctx, dbsqlc.RenameConnectedMachineTerminalSessionParams{ConnectedMachineID: machineID, ID: id, Name: name})
	if err != nil {
		return TerminalSession{}, err
	}
	if n == 0 {
		row, lookupErr := s.db.Queries().GetConnectedMachineTerminalSession(ctx, dbsqlc.GetConnectedMachineTerminalSessionParams{ID: id, ConnectedMachineID: machineID, UserID: userID})
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
	row, err := s.db.Queries().GetConnectedMachineTerminalSession(ctx, dbsqlc.GetConnectedMachineTerminalSessionParams{ID: id, ConnectedMachineID: machineID, UserID: userID})
	if err != nil {
		return TerminalSession{}, err
	}
	return mapTerminalSession(row), nil
}

// CloseTerminalSession queues a signed Papercode control operation. It returns
// false when the operation is durable but the connector is offline, allowing
// the HTTP handler to report an accepted/pending result instead of discarding
// the user's request.
func (s *Service) CloseTerminalSession(ctx context.Context, userID, machineID, id string) (bool, error) {
	if _, err := s.db.Queries().GetConnectedMachineTerminalSession(ctx, dbsqlc.GetConnectedMachineTerminalSessionParams{ID: id, ConnectedMachineID: machineID, UserID: userID}); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, ErrTerminalSessionNotFound
		}
		return false, err
	}
	n, err := s.db.Queries().CloseConnectedMachineTerminalSession(ctx, dbsqlc.CloseConnectedMachineTerminalSessionParams{ConnectedMachineID: machineID, ID: id})
	if err != nil {
		return false, err
	}
	if n > 0 {
		if err := s.db.Queries().QueueConnectedMachineTerminalSessionOperation(ctx, dbsqlc.QueueConnectedMachineTerminalSessionOperationParams{ID: newID("cmtso"), ConnectedMachineID: machineID, TerminalSessionID: id, Operation: "close"}); err != nil {
			return false, err
		}
	}
	if err := s.ApplyTerminalSessionOperations(ctx, machineID); err != nil {
		return false, nil
	}
	return true, nil
}

func (s *Service) DeleteTerminalSession(ctx context.Context, userID, machineID, id string) (bool, error) {
	row, err := s.db.Queries().GetConnectedMachineTerminalSession(ctx, dbsqlc.GetConnectedMachineTerminalSessionParams{ID: id, ConnectedMachineID: machineID, UserID: userID})
	if errors.Is(err, sql.ErrNoRows) {
		return false, ErrTerminalSessionNotFound
	}
	if err != nil {
		return false, err
	}
	if row.IsDefault {
		return false, ErrTerminalSessionReserved
	}
	n, err := s.db.Queries().DeleteConnectedMachineTerminalSession(ctx, dbsqlc.DeleteConnectedMachineTerminalSessionParams{ConnectedMachineID: machineID, ID: id})
	if err != nil {
		return false, err
	}
	if n == 0 {
		return false, ErrTerminalSessionNotFound
	}
	if err := s.db.Queries().QueueConnectedMachineTerminalSessionOperation(ctx, dbsqlc.QueueConnectedMachineTerminalSessionOperationParams{ID: newID("cmtso"), ConnectedMachineID: machineID, TerminalSessionID: id, Operation: "delete_history"}); err != nil {
		return false, err
	}
	if err := s.ApplyTerminalSessionOperations(ctx, machineID); err != nil {
		return false, nil
	}
	return true, nil
}

func (s *Service) ApplyTerminalSessionOperations(ctx context.Context, machineID string) error {
	return s.applyTerminalSessionOperations(ctx, machineID, "")
}

func (s *Service) applyTerminalSessionOperationsForSession(ctx context.Context, machineID, terminalSessionID string) error {
	return s.applyTerminalSessionOperations(ctx, machineID, terminalSessionID)
}

func (s *Service) applyTerminalSessionOperations(ctx context.Context, machineID, terminalSessionID string) error {
	for {
		items, err := s.db.Queries().ListPendingConnectedMachineTerminalSessionOperations(ctx, dbsqlc.ListPendingConnectedMachineTerminalSessionOperationsParams{ConnectedMachineID: machineID, BatchSize: 32})
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
			if err := s.applyTerminalSessionOperation(ctx, item.ID, item.ConnectedMachineID, item.TerminalSessionID, item.Operation, item.Attempts, item.UserID, item.EnvironmentID, item.AgentunnelHttpBaseUrl); err != nil {
				return err
			}
		}
		if terminalSessionID != "" {
			return nil
		}
	}
}

func (s *Service) processDueTerminalSessionOperations(ctx context.Context) error {
	items, err := s.db.Queries().ListDueConnectedMachineTerminalSessionOperations(ctx, 32)
	if err != nil {
		return err
	}
	var errs []error
	for _, item := range items {
		if err := s.applyTerminalSessionOperation(ctx, item.ID, item.ConnectedMachineID, item.TerminalSessionID, item.Operation, item.Attempts, item.UserID, item.EnvironmentID, item.AgentunnelHttpBaseUrl); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (s *Service) applyTerminalSessionOperation(ctx context.Context, operationID, machineID, terminalSessionID, operation string, attempts int32, userID, environmentID, route string) error {
	if s.controlSigner == nil || s.controlRuntime == nil || strings.TrimSpace(route) == "" || strings.TrimSpace(s.issuer) == "" {
		return s.retryTerminalSessionOperation(ctx, operationID, attempts, errors.New("connected-machine terminal control is unavailable"))
	}
	now := s.now().UTC()
	credential, err := s.controlSigner.SignCredential(mint.CredentialInput{
		Issuer: s.issuer, Audience: "paperboat-helper", Subject: userID, JTI: newID("jti"),
		IssuedAt: now, ExpiresAt: now.Add(mint.MaxProofTTL), CredentialClass: "terminal_operation", Scopes: []string{"terminal:operate"},
		EnvironmentID: environmentID, UserID: userID, ClientSessionID: operationID, SessionID: terminalSessionID,
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
			err = s.db.Queries().MarkConnectedMachineTerminalSessionRuntimeClosed(ctx, terminalSessionID)
		}
	}
	if err != nil {
		return s.retryTerminalSessionOperation(ctx, operationID, attempts, err)
	}
	return s.db.Queries().MarkConnectedMachineTerminalSessionOperationApplied(ctx, operationID)
}

func (s *Service) retryTerminalSessionOperation(ctx context.Context, id string, attempts int32, cause error) error {
	multiplier := 1 << minInt(8, int(attempts))
	backoff := multiplier
	if backoff > 300 {
		backoff = 300
	}
	err := s.db.Queries().RetryConnectedMachineTerminalSessionOperation(ctx, dbsqlc.RetryConnectedMachineTerminalSessionOperationParams{ID: id, RetrySeconds: float64(backoff), LastError: sql.NullString{String: truncateTerminalError(cause), Valid: true}})
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

func mapTerminalSession(row dbsqlc.ConnectedMachineTerminalSession) TerminalSession {
	session := TerminalSession{ID: row.ID, Name: row.Name, IsDefault: row.IsDefault, State: row.DesiredState, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt}
	if row.LastActivityAt.Valid {
		value := row.LastActivityAt.Time
		session.LastActiveAt = &value
	}
	return session
}

// Disconnect explicitly revokes the local enrollment and releases its seat.
// Offline status is intentionally not treated as disconnect.
func (s *Service) Disconnect(ctx context.Context, userID, machineID string) error {
	if err := s.revokeMachineControl(ctx, userID, machineID, false); err != nil {
		return err
	}
	auditErr := s.audit.Write(ctx, audit.Event{ActorUserID: userID, ActorType: audit.ActorUser, EventType: "connected_machine.disconnected", ResourceType: "connected_machine", ResourceID: machineID, IdempotencyKey: "connected_machine.disconnected:" + machineID, Metadata: map[string]any{}})
	return errors.Join(auditErr, s.RevokeMachineSessions(ctx, machineID, "connected_machine_disconnected"))
}

func (s *Service) Delete(ctx context.Context, userID, machineID string) error {
	if err := s.revokeMachineControl(ctx, userID, machineID, true); err != nil {
		return err
	}
	auditErr := s.audit.Write(ctx, audit.Event{ActorUserID: userID, ActorType: audit.ActorUser, EventType: "connected_machine.deleted", ResourceType: "connected_machine", ResourceID: machineID, IdempotencyKey: "connected_machine.deleted:" + machineID, Metadata: map[string]any{}})
	return errors.Join(auditErr, s.RevokeMachineSessions(ctx, machineID, "connected_machine_deleted"))
}

func (s *Service) revokeMachineControl(ctx context.Context, userID, machineID string, deleted bool) error {
	now := s.now().UTC()
	return s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		machine, err := tx.Queries().GetConnectedMachineForUpdate(ctx, dbsqlc.GetConnectedMachineForUpdateParams{ID: machineID, UserID: userID})
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		var changed int64
		if deleted {
			changed, err = tx.Queries().DeleteConnectedMachine(ctx, dbsqlc.DeleteConnectedMachineParams{ID: machineID, UserID: userID})
		} else {
			changed, err = tx.Queries().RevokeConnectedMachine(ctx, dbsqlc.RevokeConnectedMachineParams{ID: machineID, UserID: userID, State: "disconnected", SeatState: "released"})
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
	_, err = tx.Queries().RevokeControlConfigCredentialsForEnvironment(ctx, dbsqlc.RevokeControlConfigCredentialsForEnvironmentParams{EnvironmentID: environmentID, RevokedAt: sql.NullTime{Time: now, Valid: true}})
	return err
}

// RevokeMachineSessions records revocation before attempting the downstream
// call. Failed calls remain pending for Worker so revocation is eventually
// propagated without keeping the user's disconnect action hostage to an
// offline connector.
func (s *Service) RevokeMachineSessions(ctx context.Context, machineID, reason string) error {
	if strings.TrimSpace(machineID) == "" || strings.TrimSpace(reason) == "" {
		return errors.New("connected-machine revocation input is incomplete")
	}
	rows, err := s.db.Queries().RevokeConnectedMachineAccessSessions(ctx, dbsqlc.RevokeConnectedMachineAccessSessionsParams{
		ConnectedMachineID: machineID, Reason: sql.NullString{String: reason, Valid: true},
	})
	if err != nil {
		return err
	}
	var errs []error
	for _, row := range rows {
		if err := s.revokeCredentialSessions(ctx, machineAccessSession{ID: row.ID, UserID: row.UserID, ConnectedMachineID: row.ConnectedMachineID, EnvironmentID: row.EnvironmentID, ClientSessionID: row.ClientSessionID, HTTPBaseURL: row.HttpBaseUrl, TerminalSessionID: row.PapercodeTerminalSessionID, FileSessionID: row.PapercodeFileSessionID}, reason); err != nil {
			errs = append(errs, err)
			continue
		}
		if _, err := s.db.Queries().MarkConnectedMachineAccessSessionRevoked(ctx, row.ID); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// RevokeUserSessions is called after an entitlement revocation. It has the
// same durable retry behavior as an explicit machine disconnect.
func (s *Service) RevokeUserSessions(ctx context.Context, userID, reason string) error {
	if strings.TrimSpace(userID) == "" || strings.TrimSpace(reason) == "" {
		return errors.New("connected-machine user revocation input is incomplete")
	}
	rows, err := s.db.Queries().RevokeConnectedMachineAccessSessionsForUser(ctx, dbsqlc.RevokeConnectedMachineAccessSessionsForUserParams{UserID: userID, Reason: sql.NullString{String: reason, Valid: true}})
	if err != nil {
		return err
	}
	var errs []error
	for _, row := range rows {
		if err := s.revokeCredentialSessions(ctx, machineAccessSession{ID: row.ID, UserID: row.UserID, ConnectedMachineID: row.ConnectedMachineID, EnvironmentID: row.EnvironmentID, ClientSessionID: row.ClientSessionID, HTTPBaseURL: row.HttpBaseUrl, TerminalSessionID: row.PapercodeTerminalSessionID, FileSessionID: row.PapercodeFileSessionID}, reason); err != nil {
			errs = append(errs, err)
			continue
		}
		if _, err := s.db.Queries().MarkConnectedMachineAccessSessionRevoked(ctx, row.ID); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// ReconcileConnectedMachineEntitlement is safe to call after every billing
// webhook. It revokes all machines after entitlement loss and the newest
// excess machines after a seat reduction.
func (s *Service) ReconcileConnectedMachineEntitlement(ctx context.Context, userID string) error {
	if strings.TrimSpace(userID) == "" {
		return errors.New("connected-machine entitlement user is required")
	}
	now := s.now().UTC()
	var revokedMachineIDs []string
	active := false
	if err := s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		seatQuantity, err := tx.Queries().GetActiveConnectedMachineSeatQuantity(ctx, userID)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if err == nil {
			active = true
			machines, err := tx.Queries().RevokeConnectedMachinesOverSeatLimit(ctx, dbsqlc.RevokeConnectedMachinesOverSeatLimitParams{
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
		environments, err := tx.Queries().ListRevokedConnectedMachineEnvironmentsForUser(ctx, userID)
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
		for _, machineID := range revokedMachineIDs {
			errs = append(errs, s.RevokeMachineSessions(ctx, machineID, "connected_machine_seat_released"))
		}
		return errors.Join(errs...)
	}
	return s.RevokeUserSessions(ctx, userID, "connected_machine_entitlement_revoked")
}

// RetryPendingRevocations is intentionally idempotent. Papercode's signed
// revocation endpoint accepts repeated session IDs, and marking propagation is
// conditional on a still-pending row.
func (s *Service) RetryPendingRevocations(ctx context.Context) error {
	rows, err := s.db.Queries().ListPendingConnectedMachineAccessSessionRevocations(ctx)
	if err != nil {
		return err
	}
	var errs []error
	for _, row := range rows {
		reason := "revoked"
		if row.RevocationReason.Valid && strings.TrimSpace(row.RevocationReason.String) != "" {
			reason = row.RevocationReason.String
		}
		if err := s.revokeCredentialSessions(ctx, machineAccessSession{ID: row.ID, UserID: row.UserID, ConnectedMachineID: row.ConnectedMachineID, EnvironmentID: row.EnvironmentID, ClientSessionID: row.ClientSessionID, HTTPBaseURL: row.HttpBaseUrl, TerminalSessionID: row.PapercodeTerminalSessionID, FileSessionID: row.PapercodeFileSessionID}, reason); err != nil {
			errs = append(errs, err)
			continue
		}
		if _, err := s.db.Queries().MarkConnectedMachineAccessSessionRevoked(ctx, row.ID); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

type machineAccessSession struct {
	ID, UserID, ConnectedMachineID, EnvironmentID, ClientSessionID, HTTPBaseURL string
	TerminalSessionID, FileSessionID                                            string
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
		return errors.New("connected-machine credential issuer is unavailable")
	}
	if err := s.credentials.RevokeCLI(ctx, agentunnel.CredentialRevocationInput{
		UserID: session.UserID, ProjectID: session.ConnectedMachineID, EnvironmentID: session.EnvironmentID,
		ClientSessionID: session.ClientSessionID, HTTPBaseURL: session.HTTPBaseURL,
		SessionIDs: sessionIDs, Reason: reason,
	}); err != nil {
		return fmt.Errorf("revoke connected-machine sessions for %s: %w", session.ConnectedMachineID, err)
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
func mapMachine(row dbsqlc.ConnectedMachine) Machine {
	m := Machine{ID: row.ID, EnvironmentID: row.EnvironmentID, DisplayName: row.DisplayName, Platform: row.Platform, Architecture: row.Architecture, WorkspaceRoot: row.WorkspaceRoot, State: row.State, SeatState: row.SeatState, Online: row.Online, RuntimeVersions: row.RuntimeVersions}
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
