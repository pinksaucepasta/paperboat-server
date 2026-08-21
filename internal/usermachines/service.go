package usermachines

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
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
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/pinksaucepasta/paperboat-server/internal/access"
	"github.com/pinksaucepasta/paperboat-server/internal/accessdescriptor"
	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
	"github.com/pinksaucepasta/paperboat-server/internal/helperruntime"
	"github.com/pinksaucepasta/paperboat-server/internal/machinealias"
	"github.com/pinksaucepasta/paperboat-server/internal/mint"
	"github.com/pinksaucepasta/paperboat-server/internal/naming"
	"github.com/pinksaucepasta/paperboat-server/internal/secrets"
)

var (
	ErrInvalidPairing               = errors.New("invalid user-machine pairing")
	ErrInvalidSetup                 = errors.New("invalid machine setup")
	ErrMachineIdentityConflict      = errors.New("machine identity belongs to another account")
	ErrMachineNameConflict          = errors.New("machine name is already in use")
	ErrInvalidMachineName           = errors.New("invalid machine name")
	ErrPairingExpired               = errors.New("user-machine pairing expired")
	ErrPairingUsed                  = errors.New("user-machine pairing is no longer pending")
	ErrSeatUnavailable              = errors.New("user-machine seat unavailable")
	ErrNotFound                     = errors.New("user machine not found")
	ErrBandwidthDenied              = errors.New("user-machine bandwidth is unavailable")
	ErrInvalidBandwidth             = errors.New("user-machine bandwidth request is invalid")
	ErrInstallationPending          = errors.New("user-machine installation approval is pending")
	ErrInstallationDenied           = errors.New("user-machine installation was denied")
	ErrInstallationExpired          = errors.New("user-machine installation pairing expired")
	ErrInstallationUnavailable      = errors.New("user-machine installation material is unavailable")
	ErrProvisioningUnavailable      = errors.New("user-machine canonical helper provisioning is unavailable")
	ErrEnrollmentNotFound           = errors.New("user-machine enrollment not found")
	ErrEnrollmentState              = errors.New("user-machine enrollment state does not allow this operation")
	ErrIdempotencyKeyRequired       = errors.New("user-machine enrollment idempotency key is required")
	ErrTerminalSessionNotFound      = errors.New("user-machine terminal session not found")
	ErrTerminalSessionReserved      = errors.New("user-machine default terminal session is reserved")
	ErrTerminalSessionLimit         = errors.New("user-machine terminal session limit reached")
	ErrTerminalSessionConflict      = errors.New("user-machine terminal session name conflict")
	ErrTerminalSessionInvalidName   = errors.New("invalid user-machine terminal session name")
	ErrTerminalSessionIdempotency   = errors.New("terminal session idempotency key is required")
	ErrTransferDestinationInvalid   = errors.New("transfer destination is unavailable")
	ErrMachineCapabilityUnavailable = errors.New("machine capability is unavailable")
	ErrMachineOffline               = errors.New("machine is offline")
	ErrExecOperationInvalid         = errors.New("exec operation id is invalid")
	ErrSSHOperationInvalid          = errors.New("ssh operation id is invalid")
)

var terminalSessionNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
var execOperationIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{8,128}$`)

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
	helperRecovery     func(context.Context, string, string, string, string, time.Duration) (HelperEnrollmentGrant, error)
	artifactRepository string
	artifactVersion    string
	artifactVersionFn  func() string
	helperBaseDomain   string
	helperListenPort   int32
	cliClientID        string
	cliScopes          string
	cliAccessLifetime  time.Duration
	cliRefreshLifetime time.Duration
	cliHashKey         []byte
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

type MachineArtifact struct {
	Schema        string `json:"schema"`
	Kind          string `json:"kind"`
	Version       string `json:"version"`
	Platform      string `json:"platform"`
	Architecture  string `json:"architecture"`
	RepositoryURL string `json:"repository_url"`
	TargetPath    string `json:"target_path"`
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

// ConfigureOneShotCLIAuth enables the session issued by an approved machine
// enrollment. It is deliberately separate from the machine credential: the
// material contains ordinary CLI tokens, while host credentials remain scoped
// to the enrolled runtime.
func (s *Service) ConfigureOneShotCLIAuth(clientID string, scopes []string, accessLifetime, refreshLifetime time.Duration, hashKey string) {
	s.cliClientID = strings.TrimSpace(clientID)
	s.cliScopes = strings.Join(slices.Compact(slices.Clone(scopes)), " ")
	s.cliAccessLifetime, s.cliRefreshLifetime = accessLifetime, refreshLifetime
	s.cliHashKey = []byte(hashKey)
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

func (s *Service) ConfigureRuntimeRoute(baseDomain string, listenPort int32) error {
	baseDomain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(baseDomain), "."))
	if baseDomain == "" || listenPort < 1024 || listenPort > 65535 {
		return errors.New("machine runtime route configuration is invalid")
	}
	s.helperBaseDomain, s.helperListenPort = baseDomain, listenPort
	return nil
}

func (s *Service) ConfigureHelperEnrollment(issuer func(context.Context, string, string, string, time.Duration) (HelperEnrollmentGrant, error)) {
	s.helperGrant = issuer
}

func (s *Service) ConfigureHelperRecovery(recover func(context.Context, string, string, string, string, time.Duration) (HelperEnrollmentGrant, error)) {
	s.helperRecovery = recover
}

func (s *Service) ConfigureMachineArtifacts(repositoryURL, version string) error {
	repositoryURL, version = strings.TrimRight(strings.TrimSpace(repositoryURL), "/"), strings.TrimSpace(version)
	if repositoryURL == "" && version == "" {
		return nil
	}
	parsed, err := url.Parse(repositoryURL)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Hostname() == "" || parsed.RawQuery != "" || parsed.Fragment != "" || version == "" || len(version) > 64 || strings.ContainsAny(version, "\x00\r\n/\\") {
		return errors.New("user-machine artifacts are invalid")
	}
	s.artifactRepository, s.artifactVersion = repositoryURL, version
	return nil
}

func (s *Service) ConfigureMachineArtifactVersionResolver(resolve func() string) {
	s.artifactVersionFn = resolve
}

func (s *Service) machineArtifact(platform, architecture string) (MachineArtifact, bool) {
	version := s.artifactVersion
	if s.artifactVersionFn != nil {
		version = strings.TrimSpace(s.artifactVersionFn())
	}
	if s.artifactRepository == "" || version == "" || len(version) > 64 || strings.ContainsAny(version, "\x00\r\n/\\") || !slices.Contains([]string{"darwin", "linux", "windows"}, platform) || !slices.Contains([]string{"amd64", "arm64"}, architecture) {
		return MachineArtifact{}, false
	}
	return MachineArtifact{Schema: "paperboat.tuf-target/v1", Kind: "pb", Version: version, Platform: platform, Architecture: architecture, RepositoryURL: s.artifactRepository, TargetPath: "pb-" + platform + "-" + architecture}, true
}

func New(store *db.DB, auditWriter *audit.Writer, policy Policy, seats SeatAuthorizer) *Service {
	if policy.OfflineAfter <= 0 {
		policy.OfflineAfter = 2 * time.Minute
	}
	return &Service{db: store, audit: auditWriter, policy: policy, seats: seats, now: time.Now, maxSessions: 20}
}

type PairingInput struct {
	Verifier, EnrollmentToken, DisplayName, Platform, Architecture, WorkspaceRoot, PublicIdentityKey string
	SSHUser                                                                                          string
	SSHPort                                                                                          uint16
	RuntimeVersions                                                                                  json.RawMessage
	AcceptBetaPlatform                                                                               bool
	CanReuseRuntimeIdentity                                                                          bool
}

type Enrollment struct {
	ID                   string     `json:"id"`
	OperationID          string     `json:"operation_id"`
	State                string     `json:"state"`
	Generation           int64      `json:"generation"`
	PairingID            string     `json:"pairing_id,omitempty"`
	UserCode             string     `json:"user_code,omitempty"`
	UserMachineID        string     `json:"machine_id,omitempty"`
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
	// BootstrapToken is a short-lived, single-use credential. It is returned
	// only when an enrollment is created so the dashboard can render one
	// paste-once command. It is never persisted in plaintext or logged.
	BootstrapToken    string `json:"bootstrap_token"`
	BootstrapCommand  string `json:"bootstrap_command"`
	TokenDownloadPath string `json:"token_download_path"`
	ServerURL         string `json:"server_url"`
}

type EnrollmentOptions struct {
	Role  string // host or client
	Shell string // posix or powershell
}

func (s *Service) StartEnrollment(ctx context.Context, userID, idempotencyKey string) (EnrollmentStart, error) {
	return s.StartEnrollmentWithOptions(ctx, userID, idempotencyKey, EnrollmentOptions{Role: "host", Shell: "posix"})
}

func (s *Service) StartEnrollmentWithOptions(ctx context.Context, userID, idempotencyKey string, options EnrollmentOptions) (EnrollmentStart, error) {
	userID, idempotencyKey = strings.TrimSpace(userID), strings.TrimSpace(idempotencyKey)
	if userID == "" || idempotencyKey == "" || len(idempotencyKey) > 128 {
		return EnrollmentStart{}, ErrIdempotencyKeyRequired
	}
	if strings.TrimSpace(s.encryptionKey) == "" {
		return EnrollmentStart{}, errors.New("user-machine enrollment encryption is not configured")
	}
	token, err := randomEnrollmentTokenFor(options.Role, options.Shell)
	if err != nil {
		return EnrollmentStart{}, err
	}
	hash := enrollmentTokenHash(token)
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
	result := s.enrollmentStart(row, token)
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
	return s.RetryEnrollmentWithOptions(ctx, userID, enrollmentID, EnrollmentOptions{Role: "host", Shell: "posix"})
}

func (s *Service) RetryEnrollmentWithOptions(ctx context.Context, userID, enrollmentID string, options EnrollmentOptions) (EnrollmentStart, error) {
	if strings.TrimSpace(s.encryptionKey) == "" {
		return EnrollmentStart{}, errors.New("user-machine enrollment encryption is not configured")
	}
	token, err := randomEnrollmentTokenFor(options.Role, options.Shell)
	if err != nil {
		return EnrollmentStart{}, err
	}
	hash := enrollmentTokenHash(token)
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
	return s.enrollmentStart(row, token), nil
}

func (s *Service) enrollmentStart(row dbsqlc.UserMachineEnrollment, token string) EnrollmentStart {
	return EnrollmentStart{
		Enrollment:        mapEnrollment(row),
		BootstrapToken:    token,
		BootstrapCommand:  strings.TrimSpace(s.bootstrapCommand),
		TokenDownloadPath: "/v1/machine-enrollments/" + row.ID + "/bootstrap-token",
		ServerURL:         strings.TrimRight(strings.TrimSpace(s.issuer), "/"),
	}
}

// EnrollmentToken returns the short-lived bootstrap bearer only to the
// authenticated enrollment owner. It remains available for compatibility with
// older clients; new enrollment uses the one-shot command returned at start.
func (s *Service) EnrollmentToken(ctx context.Context, userID, enrollmentID string) (string, error) {
	row, err := s.db.Queries().GetUserMachineEnrollmentForUser(ctx, dbsqlc.GetUserMachineEnrollmentForUserParams{ID: strings.TrimSpace(enrollmentID), UserID: strings.TrimSpace(userID)})
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrEnrollmentNotFound
	}
	if err != nil {
		return "", err
	}
	if row.State != "awaiting_bootstrap" || !s.now().UTC().Before(row.ExpiresAt) {
		return "", ErrEnrollmentState
	}
	token, err := secrets.Decrypt(s.encryptionKey, row.BootstrapTokenCiphertext)
	if _, ok := enrollmentTokenSecret(token); err != nil || !ok {
		return "", ErrEnrollmentState
	}
	return token, nil
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

type SetupInput struct {
	DisplayName, Platform, Architecture, WorkspaceRoot, PublicIdentityKey string
	SetupMode                                                             string
	RuntimeVersions                                                       json.RawMessage
	AcceptBetaPlatform                                                    bool
}

func (s *Service) Setup(ctx context.Context, userID string, in SetupInput) (UserMachine, error) {
	userID = strings.TrimSpace(userID)
	workspaceRoot, validWorkspace := canonicalWorkspaceRoot(in.Platform, in.WorkspaceRoot)
	publicKey, keyErr := base64.RawURLEncoding.DecodeString(strings.TrimSpace(in.PublicIdentityKey))
	if userID == "" || !slices.Contains([]string{"host", "receive", "session"}, in.SetupMode) || invalidMachineDisplayName(in.DisplayName) || !validMachineArchitecture(in.Architecture) ||
		!validWorkspace ||
		!slices.Contains(s.policy.AllowedPlatforms, strings.ToLower(strings.TrimSpace(in.Platform))) ||
		isUnacceptedBetaPlatform(in.Platform, in.Architecture, in.AcceptBetaPlatform) ||
		keyErr != nil || len(publicKey) != ed25519.PublicKeySize {
		return UserMachine{}, ErrInvalidSetup
	}
	in.WorkspaceRoot = workspaceRoot
	if len(in.RuntimeVersions) == 0 {
		in.RuntimeVersions = json.RawMessage(`{}`)
	}
	var result UserMachine
	var downgradedFromHost bool
	err := s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		key := sql.NullString{String: strings.TrimSpace(in.PublicIdentityKey), Valid: true}
		row, err := tx.Queries().GetUserMachineByPublicIdentityForUpdate(ctx, key)
		if err == nil {
			if row.UserID != userID {
				return ErrMachineIdentityConflict
			}
			if row.Platform != strings.ToLower(strings.TrimSpace(in.Platform)) || row.Architecture != strings.ToLower(strings.TrimSpace(in.Architecture)) || row.WorkspaceRoot != in.WorkspaceRoot {
				return ErrInvalidSetup
			}
			wasHost := row.SetupMode == "host" || slices.Contains(row.SetupRoles, "host")
			row, err = tx.Queries().AddUserMachineInteractiveRole(ctx, dbsqlc.AddUserMachineInteractiveRoleParams{ID: row.ID, UserID: userID, DisplayName: strings.TrimSpace(in.DisplayName), RuntimeVersions: in.RuntimeVersions, SetupMode: in.SetupMode, ConfiguredCapabilities: configuredCapabilities(in.SetupMode)})
			if err != nil {
				return err
			}
			if wasHost && in.SetupMode != "host" {
				downgradedFromHost = true
				if err := s.revokeHostAuthorityTx(ctx, tx, row.ID, row.EnvironmentID, s.now().UTC()); err != nil {
					return err
				}
			}
			if in.SetupMode == "session" {
				if _, err := tx.Queries().RevokeControlRoutesForEnvironment(ctx, dbsqlc.RevokeControlRoutesForEnvironmentParams{EnvironmentID: row.EnvironmentID, Now: s.now().UTC()}); err != nil {
					return err
				}
			}
			if in.SetupMode == "receive" {
				if err := s.ensureHelperRoute(ctx, tx, row.ID, row.EnvironmentID); err != nil {
					return err
				}
				if _, err := s.ensureCurrentBandwidthPeriod(ctx, tx, row); err != nil {
					return err
				}
			}
			result = mapMachine(row)
			return s.audit.WriteTx(ctx, tx, audit.Event{ActorUserID: userID, ActorType: audit.ActorUser, EventType: "machine.setup_resumed", ResourceType: "machine", ResourceID: row.ID, IdempotencyKey: "machine.setup_resumed:" + row.ID + ":" + strconv.FormatInt(row.Version, 10)})
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		environmentID := newID("env")
		alias, err := allocateMachineAlias(ctx, tx.Queries(), userID, in.DisplayName)
		if err != nil {
			return err
		}
		row, err = tx.Queries().CreateInteractiveMachine(ctx, dbsqlc.CreateInteractiveMachineParams{
			ID: newID("mch"), UserID: userID, EnvironmentID: environmentID, DisplayName: strings.TrimSpace(in.DisplayName), Alias: alias,
			Platform: strings.ToLower(strings.TrimSpace(in.Platform)), Architecture: strings.ToLower(strings.TrimSpace(in.Architecture)),
			WorkspaceRoot: in.WorkspaceRoot, RuntimeVersions: in.RuntimeVersions, SetupMode: in.SetupMode, ConfiguredCapabilities: configuredCapabilities(in.SetupMode), PublicIdentityKey: key,
		})
		if userMachineTerminalSessionUniqueViolation(err) {
			return ErrMachineNameConflict
		}
		if err != nil {
			return err
		}
		if _, err := tx.Queries().CreateControlEnvironment(ctx, dbsqlc.CreateControlEnvironmentParams{ID: environmentID, WorkspaceID: row.ID, OwnerUserID: sql.NullString{String: userID, Valid: true}, DesiredState: "active"}); err != nil {
			return err
		}
		if in.SetupMode == "receive" {
			if err := s.ensureHelperRoute(ctx, tx, row.ID, row.EnvironmentID); err != nil {
				return err
			}
			if _, err := s.ensureCurrentBandwidthPeriod(ctx, tx, row); err != nil {
				return err
			}
		}
		result = mapMachine(row)
		return s.audit.WriteTx(ctx, tx, audit.Event{ActorUserID: userID, ActorType: audit.ActorUser, EventType: "machine.setup", ResourceType: "machine", ResourceID: row.ID, IdempotencyKey: "machine.setup:" + row.ID})
	})
	if err == nil && downgradedFromHost {
		err = s.RevokeUserMachineSessions(ctx, result.ID, "machine_mode_downgraded")
	}
	if err == nil && in.SetupMode == "receive" {
		artifact, ok := s.machineArtifact(result.Platform, result.Architecture)
		if !ok || s.issuer == "" || s.helperListenPort == 0 {
			return UserMachine{}, ErrProvisioningUnavailable
		}
		result.Installation = &ReceiveInstallation{ControlURL: s.issuer, HelperListenAddress: fmt.Sprintf("127.0.0.1:%d", s.helperListenPort), Artifact: artifact}
	}
	return result, err
}

func (s *Service) CreatePairing(ctx context.Context, in PairingInput) (Pairing, error) {
	if err := s.validatePairing(in); err != nil {
		return Pairing{}, err
	}
	in.WorkspaceRoot, _ = canonicalWorkspaceRoot(in.Platform, in.WorkspaceRoot)
	verifierHash := sha256.Sum256([]byte(in.Verifier))
	code, err := randomCode(8)
	if err != nil {
		return Pairing{}, err
	}
	if len(in.RuntimeVersions) == 0 {
		in.RuntimeVersions = json.RawMessage(`{}`)
	}
	expires := s.now().UTC().Add(s.policy.PairingLifetime)
	params := dbsqlc.CreateUserMachinePairingParams{ID: newID("ump"), VerifierHash: verifierHash[:], UserCode: code, RequestedDisplayName: strings.TrimSpace(in.DisplayName), Platform: strings.ToLower(strings.TrimSpace(in.Platform)), Architecture: strings.ToLower(strings.TrimSpace(in.Architecture)), WorkspaceRoot: in.WorkspaceRoot, RuntimeVersions: in.RuntimeVersions, PublicIdentityKey: strings.TrimSpace(in.PublicIdentityKey), CanReuseRuntimeIdentity: in.CanReuseRuntimeIdentity, ExpiresAt: expires}
	if in.SSHUser != "" || in.SSHPort != 0 {
		params.SshUser = sql.NullString{String: strings.TrimSpace(in.SSHUser), Valid: true}
		params.SshPort = sql.NullInt32{Int32: int32(in.SSHPort), Valid: true}
	}
	var row dbsqlc.UserMachinePairing
	var enrollmentUserID string
	setupMode := "host"
	if strings.TrimSpace(in.EnrollmentToken) == "" {
		row, err = s.db.Queries().CreateUserMachinePairing(ctx, params)
	} else {
		token := strings.TrimSpace(in.EnrollmentToken)
		if len(token) == enrollmentTokenLength && !strings.Contains("02468BDFHJLNPRTVXZ", token[:1]) {
			setupMode = "receive"
		}
		tokenHash := enrollmentTokenHash(token)
		err = s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
			enrollment, err := tx.Queries().GetUserMachineEnrollmentForTokenUpdate(ctx, tokenHash[:])
			if errors.Is(err, sql.ErrNoRows) {
				// Transitional compatibility for enrollments created before metadata
				// was separated from the credential hash.
				legacyHash := sha256.Sum256([]byte(token))
				enrollment, err = tx.Queries().GetUserMachineEnrollmentForTokenUpdate(ctx, legacyHash[:])
				if errors.Is(err, sql.ErrNoRows) {
					return ErrEnrollmentNotFound
				}
			}
			if err != nil {
				return err
			}
			if enrollment.State != "awaiting_bootstrap" || !s.now().UTC().Before(enrollment.ExpiresAt) {
				return ErrEnrollmentState
			}
			enrollmentUserID = enrollment.UserID
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
	// A dashboard-issued enrollment token is already authenticated by the
	// account owner. Consume the approval step immediately so a pasted command
	// is genuinely one-shot. The explicit pairing approval endpoint remains only
	// for legacy pairing requests that did not carry an enrollment token.
	if enrollmentUserID != "" {
		if _, err := s.approve(ctx, enrollmentUserID, row.UserCode, setupMode); err != nil {
			return Pairing{}, err
		}
	}
	return Pairing{ID: row.ID, UserCode: row.UserCode, ExpiresAt: row.ExpiresAt}, nil
}

type UserMachine struct {
	ID                     string               `json:"id"`
	EnvironmentID          string               `json:"environment_id"`
	DisplayName            string               `json:"display_name"`
	Alias                  string               `json:"alias"`
	Platform               string               `json:"platform"`
	Architecture           string               `json:"architecture"`
	WorkspaceRoot          string               `json:"workspace_root"`
	State                  string               `json:"state"`
	SeatState              string               `json:"seat_state"`
	Online                 bool                 `json:"online"`
	RuntimeVersions        json.RawMessage      `json:"runtime_versions"`
	SetupRoles             []string             `json:"setup_roles"`
	SetupMode              string               `json:"setup_mode"`
	Capabilities           MachineCapabilities  `json:"capabilities"`
	MachineKind            string               `json:"machine_kind"`
	PublicIdentityKey      string               `json:"public_identity_key"`
	InstallationGeneration int64                `json:"installation_generation"`
	EnrolledAt             *time.Time           `json:"enrolled_at,omitempty"`
	LastSeenAt             *time.Time           `json:"last_seen_at,omitempty"`
	Availability           AvailabilityPolicy   `json:"availability"`
	RuntimeDiagnostics     RuntimeDiagnostics   `json:"runtime_diagnostics"`
	Installation           *ReceiveInstallation `json:"installation,omitempty"`
}

type ReceiveInstallation struct {
	ControlURL          string          `json:"control_url"`
	HelperListenAddress string          `json:"helper_listen_address"`
	Artifact            MachineArtifact `json:"artifact"`
}

type CapabilityAvailability struct {
	Configured bool `json:"configured"`
	Observed   bool `json:"observed"`
}

type MachineCapabilities struct {
	FileReceive   CapabilityAvailability `json:"file_receive"`
	PreviewLaunch CapabilityAvailability `json:"preview_launch"`
	TerminalHost  CapabilityAvailability `json:"terminal_host"`
	CodexHost     CapabilityAvailability `json:"codex_host"`
	SessionHost   CapabilityAvailability `json:"session_host"`
	KeepAwake     CapabilityAvailability `json:"keep_awake"`
}

func configuredCapabilities(mode string) []string {
	switch mode {
	case "receive":
		return []string{"file_receive", "preview_launch"}
	case "host":
		return []string{"file_receive", "preview_launch", "terminal_host", "codex_host", "session_host", "keep_awake"}
	default:
		return []string{}
	}
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
	EvictedSession *TerminalSession `json:"evicted_session,omitempty"`
}

// BandwidthReservation is a trusted capacity grant. A data-plane relay must
// forward no more than GrantedBytes before requesting another grant.
type BandwidthReservation struct {
	GrantedBytes int64 `json:"granted_bytes"`
	Exhausted    bool  `json:"exhausted"`
}

func (s *Service) TransferDestinationDefault(ctx context.Context, userID string) (UserMachine, error) {
	row, err := s.db.Queries().GetUserTransferDestinationDefault(ctx, userID)
	if errors.Is(err, sql.ErrNoRows) {
		return UserMachine{}, ErrNotFound
	}
	if err != nil {
		return UserMachine{}, err
	}
	return mapMachine(row), nil
}

func (s *Service) SetTransferDestinationDefault(ctx context.Context, userID, machineID string) (UserMachine, error) {
	var result UserMachine
	err := s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		if _, err := tx.Queries().SetUserTransferDestinationDefault(ctx, dbsqlc.SetUserTransferDestinationDefaultParams{UserID: userID, MachineID: machineID}); errors.Is(err, sql.ErrNoRows) {
			return ErrTransferDestinationInvalid
		} else if err != nil {
			return err
		}
		row, err := tx.Queries().GetUserMachineForUser(ctx, dbsqlc.GetUserMachineForUserParams{ID: machineID, UserID: userID})
		if err != nil {
			return err
		}
		result = mapMachine(row)
		return s.audit.WriteTx(ctx, tx, audit.Event{ActorUserID: userID, ActorType: audit.ActorUser, EventType: "transfer_destination.default_set", ResourceType: "user", ResourceID: userID, Metadata: map[string]any{"machine_id": machineID}})
	})
	return result, err
}

func (s *Service) ClearTransferDestinationDefault(ctx context.Context, userID string) error {
	return s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		changed, err := tx.Queries().ClearUserTransferDestinationDefault(ctx, userID)
		if err != nil || changed == 0 {
			return err
		}
		return s.audit.WriteTx(ctx, tx, audit.Event{ActorUserID: userID, ActorType: audit.ActorUser, EventType: "transfer_destination.default_cleared", ResourceType: "user", ResourceID: userID})
	})
}

func (s *Service) TerminalSessionTransferDestination(ctx context.Context, userID, sessionID string) (UserMachine, error) {
	row, err := s.db.Queries().GetTerminalSessionTransferDestination(ctx, dbsqlc.GetTerminalSessionTransferDestinationParams{SessionID: sessionID, UserID: userID})
	if errors.Is(err, sql.ErrNoRows) {
		return UserMachine{}, ErrNotFound
	}
	if err != nil {
		return UserMachine{}, err
	}
	return mapMachine(row), nil
}

func (s *Service) SetTerminalSessionTransferDestination(ctx context.Context, userID, sessionID, machineID string) (UserMachine, error) {
	var result UserMachine
	err := s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		row, err := tx.Queries().SetTerminalSessionTransferDestination(ctx, dbsqlc.SetTerminalSessionTransferDestinationParams{MachineID: machineID, UserID: userID, SessionID: sessionID})
		if errors.Is(err, sql.ErrNoRows) {
			return ErrTransferDestinationInvalid
		}
		if err != nil {
			return err
		}
		result = mapMachine(row)
		return s.audit.WriteTx(ctx, tx, audit.Event{ActorUserID: userID, ActorType: audit.ActorUser, EventType: "transfer_destination.session_set", ResourceType: "terminal_session", ResourceID: sessionID, Metadata: map[string]any{"machine_id": machineID}})
	})
	return result, err
}

func (s *Service) ClearTerminalSessionTransferDestination(ctx context.Context, userID, sessionID string) error {
	return s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		if _, err := tx.Queries().ClearTerminalSessionTransferDestination(ctx, dbsqlc.ClearTerminalSessionTransferDestinationParams{SessionID: sessionID, UserID: userID}); errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		return s.audit.WriteTx(ctx, tx, audit.Event{ActorUserID: userID, ActorType: audit.ActorUser, EventType: "transfer_destination.session_cleared", ResourceType: "terminal_session", ResourceID: sessionID})
	})
}

func (s *Service) EligibleTerminalSessionTransferDestinations(ctx context.Context, userID, cliClientSessionID, sessionID string) ([]UserMachine, error) {
	if s.controlSigner == nil || cliClientSessionID == "" {
		return nil, ErrProvisioningUnavailable
	}
	host, err := s.db.Queries().GetUserMachineTerminalSessionHostForUser(ctx, dbsqlc.GetUserMachineTerminalSessionHostForUserParams{SessionID: sessionID, UserID: userID})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrTerminalSessionNotFound
	}
	if err != nil {
		return nil, err
	}
	route, err := s.db.Queries().GetActiveHelperRouteForEnvironment(ctx, host.EnvironmentID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrProvisioningUnavailable
	}
	if err != nil {
		return nil, err
	}
	now := s.now().UTC()
	expires := now.Add(2 * time.Minute)
	token, err := s.controlSigner.SignCredential(mint.CredentialInput{
		Issuer: s.issuer, Audience: "paperboat-machine", Subject: userID, JTI: newID("jti_helper_terminal"),
		IssuedAt: now, ExpiresAt: expires, CredentialClass: "terminal_operation", Scopes: []string{"terminal:operate"},
		EnvironmentID: host.EnvironmentID, MachineID: host.ID, UserID: userID, CLIClientSessionID: cliClientSessionID, SessionID: sessionID,
	})
	if err != nil {
		return nil, err
	}
	snapshot, err := s.controlRuntime.Terminal(ctx, "https://"+route.PublicHost, token, "transfer-destinations", sessionID, newID("op_transfer_destinations"))
	if err != nil {
		return nil, err
	}
	result := make([]UserMachine, 0, len(snapshot.EligibleTransferDestinationMachineIDs))
	for _, machineID := range snapshot.EligibleTransferDestinationMachineIDs {
		row, lookupErr := s.db.Queries().GetUserMachineForUser(ctx, dbsqlc.GetUserMachineForUserParams{ID: machineID, UserID: userID})
		if lookupErr == nil && row.State != "revoked" && row.State != "disconnected" && row.State != "deleted" && row.SeatState == "occupied" {
			result = append(result, mapMachine(row))
		}
	}
	return result, nil
}

func (s *Service) OwnedEligibleMachines(ctx context.Context, userID string, machineIDs []string) ([]UserMachine, error) {
	result := make([]UserMachine, 0, len(machineIDs))
	for _, machineID := range machineIDs {
		row, err := s.db.Queries().GetUserMachineForUser(ctx, dbsqlc.GetUserMachineForUserParams{ID: machineID, UserID: userID})
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if row.State != "revoked" && row.State != "disconnected" && row.State != "deleted" && row.SeatState == "occupied" {
			result = append(result, mapMachine(row))
		}
	}
	return result, nil
}

type ConnectionDescriptor struct {
	Schema            string         `json:"schema,omitempty"`
	Capabilities      []string       `json:"capabilities,omitempty"`
	Issuer            string         `json:"issuer,omitempty"`
	UserMachineID     string         `json:"machine_id"`
	UserMachineState  string         `json:"machine_state"`
	Connectable       bool           `json:"connectable"`
	ExpiresAt         time.Time      `json:"expires_at"`
	Environment       map[string]any `json:"environment,omitempty"`
	Terminal          map[string]any `json:"terminal,omitempty"`
	FileTransfer      map[string]any `json:"file_transfer,omitempty"`
	Status            string         `json:"status,omitempty"`
	Reason            string         `json:"reason,omitempty"`
	RetryAfterSeconds int            `json:"retry_after_seconds,omitempty"`
}

type ExecDescriptor struct {
	OperationID string         `json:"operation_id"`
	Environment map[string]any `json:"environment"`
	Endpoints   map[string]any `json:"endpoints"`
	Auth        map[string]any `json:"auth"`
	ExpiresAt   time.Time      `json:"expires_at"`
}

type SSHDescriptor = ExecDescriptor

func (s *Service) ExecDescriptor(ctx context.Context, userID, sourceMachineID, userMachineID, cliClientSessionID, operationID string) (ExecDescriptor, error) {
	return s.operationDescriptor(ctx, userID, sourceMachineID, userMachineID, cliClientSessionID, operationID, "exec_operation", "exec:operate", "jti_helper_exec", ErrExecOperationInvalid)
}

func (s *Service) SSHDescriptor(ctx context.Context, userID, sourceMachineID, userMachineID, cliClientSessionID, operationID string) (SSHDescriptor, error) {
	return s.operationDescriptor(ctx, userID, sourceMachineID, userMachineID, cliClientSessionID, operationID, "ssh_operation", "ssh:operate", "jti_helper_ssh", ErrSSHOperationInvalid)
}

func (s *Service) operationDescriptor(ctx context.Context, userID, sourceMachineID, userMachineID, cliClientSessionID, operationID, credentialClass, scope, jtiPrefix string, invalidOperationErr error) (ExecDescriptor, error) {
	if !execOperationIDPattern.MatchString(operationID) {
		return ExecDescriptor{}, invalidOperationErr
	}
	if sourceMachineID == "" || sourceMachineID == userMachineID || cliClientSessionID == "" {
		return ExecDescriptor{}, ErrNotFound
	}
	if _, err := s.db.Queries().GetUserMachineForUser(ctx, dbsqlc.GetUserMachineForUserParams{ID: sourceMachineID, UserID: userID}); err != nil {
		return ExecDescriptor{}, ErrNotFound
	}
	row, err := s.db.Queries().GetUserMachineForUser(ctx, dbsqlc.GetUserMachineForUserParams{ID: userMachineID, UserID: userID})
	if errors.Is(err, sql.ErrNoRows) {
		return ExecDescriptor{}, ErrNotFound
	}
	if err != nil {
		return ExecDescriptor{}, err
	}
	if row.State != "online" || row.SeatState != "occupied" || !row.Online || !slices.Contains(row.ObservedCapabilities, "terminal_host") || !slices.Contains(row.ConfiguredCapabilities, "terminal_host") {
		return ExecDescriptor{}, ErrMachineCapabilityUnavailable
	}
	if credentialClass == "ssh_operation" {
		target, targetErr := s.db.Queries().GetMachineSSHTargetForUpdate(ctx, row.ID)
		if targetErr != nil || target.MachineGeneration != row.InstallationGeneration {
			if targetErr != nil && !errors.Is(targetErr, sql.ErrNoRows) {
				return ExecDescriptor{}, targetErr
			}
			return ExecDescriptor{}, ErrMachineCapabilityUnavailable
		}
		keys, keysErr := s.db.Queries().GetActiveMachineSSHHostKeySetForUpdate(ctx, row.ID)
		if keysErr != nil || keys.MachineGeneration != row.InstallationGeneration {
			if keysErr != nil && !errors.Is(keysErr, sql.ErrNoRows) {
				return ExecDescriptor{}, keysErr
			}
			return ExecDescriptor{}, ErrMachineCapabilityUnavailable
		}
	}
	route, err := s.db.Queries().GetActiveHelperRouteForEnvironment(ctx, row.EnvironmentID)
	if errors.Is(err, sql.ErrNoRows) {
		return ExecDescriptor{}, ErrMachineCapabilityUnavailable
	}
	if err != nil {
		return ExecDescriptor{}, err
	}
	if s.controlSigner == nil {
		return ExecDescriptor{}, errors.New("user-machine exec credential issuer is unavailable")
	}
	ttl := s.ttl
	if ttl <= 0 || ttl > 5*time.Minute {
		ttl = 5 * time.Minute
	}
	issuedAt := s.now().UTC()
	expiresAt := issuedAt.Add(ttl)
	operationJTI := newID(jtiPrefix)
	token, err := s.controlSigner.SignCredential(mint.CredentialInput{
		Issuer: s.issuer, Audience: "paperboat-machine", Subject: userID, JTI: operationJTI,
		IssuedAt: issuedAt, ExpiresAt: expiresAt, CredentialClass: credentialClass, Scopes: []string{scope},
		EnvironmentID: row.EnvironmentID, MachineID: row.ID, UserID: userID, CLIClientSessionID: cliClientSessionID, OperationID: operationID,
	})
	if err != nil {
		return ExecDescriptor{}, err
	}
	if err := s.db.Queries().CreateUserMachineAccessSession(ctx, dbsqlc.CreateUserMachineAccessSessionParams{
		ID: newID("umas"), UserMachineID: row.ID, UserID: userID, EnvironmentID: row.EnvironmentID,
		CLIClientSessionID: cliClientSessionID, HttpBaseUrl: "https://" + route.PublicHost,
		HelperTerminalSessionID: operationJTI, HelperFileSessionID: "", ExpiresAt: expiresAt,
	}); err != nil {
		return ExecDescriptor{}, err
	}
	return ExecDescriptor{
		OperationID: operationID,
		Environment: map[string]any{"id": row.EnvironmentID, "kind": accessdescriptor.EnvironmentBYOD, "resource_id": row.ID, "display_name": row.DisplayName, "state": "ready", "root": row.WorkspaceRoot},
		Endpoints:   machineTerminalEndpoints("wss://" + route.PublicHost),
		Auth:        map[string]any{"method": "bearer", "token": token, "expires_at": expiresAt, "scopes": []string{scope}},
		ExpiresAt:   expiresAt,
	}, nil
}

type FileTransferDescriptor struct {
	Endpoint             string                              `json:"endpoint"`
	SourceMachineID      string                              `json:"source_machine_id"`
	DestinationMachineID string                              `json:"destination_machine_id"`
	InitiatingUserID     string                              `json:"initiating_user_id"`
	Auth                 map[string]any                      `json:"auth"`
	Policy               accessdescriptor.FileTransferPolicy `json:"policy"`
}

type PreviewLaunchDescriptor struct {
	Endpoint  string         `json:"endpoint"`
	MachineID string         `json:"machine_id"`
	ExpiresAt time.Time      `json:"expires_at"`
	Auth      map[string]any `json:"auth"`
}

func (s *Service) PreviewLaunchDescriptor(ctx context.Context, userID, machineID, cliClientSessionID string) (PreviewLaunchDescriptor, error) {
	if userID == "" || machineID == "" || cliClientSessionID == "" || s.controlSigner == nil {
		return PreviewLaunchDescriptor{}, ErrProvisioningUnavailable
	}
	row, err := s.db.Queries().GetUserMachineForUser(ctx, dbsqlc.GetUserMachineForUserParams{ID: machineID, UserID: userID})
	if errors.Is(err, sql.ErrNoRows) {
		return PreviewLaunchDescriptor{}, ErrNotFound
	}
	if err != nil {
		return PreviewLaunchDescriptor{}, err
	}
	if !slices.Contains(row.ConfiguredCapabilities, "preview_launch") {
		return PreviewLaunchDescriptor{}, ErrMachineCapabilityUnavailable
	}
	if !row.Online || !slices.Contains(row.ObservedCapabilities, "preview_launch") {
		return PreviewLaunchDescriptor{}, ErrMachineOffline
	}
	if row.State == "revoked" || row.State == "disconnected" || row.State == "deleted" {
		return PreviewLaunchDescriptor{}, ErrProvisioningUnavailable
	}
	route, err := s.db.Queries().GetActiveHelperRouteForEnvironment(ctx, row.EnvironmentID)
	if errors.Is(err, sql.ErrNoRows) {
		return PreviewLaunchDescriptor{}, ErrProvisioningUnavailable
	}
	if err != nil {
		return PreviewLaunchDescriptor{}, err
	}
	now := s.now().UTC()
	expires := now.Add(2 * time.Minute)
	token, err := s.controlSigner.SignCredential(mint.CredentialInput{
		Issuer: s.issuer, Audience: "paperboat-machine", Subject: userID, JTI: newID("jti_preview_launch"),
		IssuedAt: now, ExpiresAt: expires, CredentialClass: "preview_launch", Scopes: []string{"preview:launch"},
		EnvironmentID: row.EnvironmentID, MachineID: row.ID, UserID: userID, CLIClientSessionID: cliClientSessionID,
	})
	if err != nil {
		return PreviewLaunchDescriptor{}, err
	}
	return PreviewLaunchDescriptor{
		Endpoint: "https://" + route.PublicHost + "/v1/preview-launches", MachineID: row.ID, ExpiresAt: expires,
		Auth: map[string]any{"method": "bearer", "token": token, "expires_at": expires, "scopes": []string{"preview:launch"}},
	}, nil
}

func (s *Service) FileTransferDescriptor(ctx context.Context, userID, sourceMachineID, destinationMachineID, cliClientSessionID, sessionID string) (FileTransferDescriptor, error) {
	if sourceMachineID == "" || destinationMachineID == "" || sourceMachineID == destinationMachineID || cliClientSessionID == "" || s.controlSigner == nil {
		return FileTransferDescriptor{}, ErrNotFound
	}
	if _, err := s.db.Queries().GetUserMachineForUser(ctx, dbsqlc.GetUserMachineForUserParams{ID: sourceMachineID, UserID: userID}); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return FileTransferDescriptor{}, ErrNotFound
		}
		return FileTransferDescriptor{}, err
	}
	if sessionID != "" {
		owned, err := s.db.Queries().UserOwnsTerminalSession(ctx, dbsqlc.UserOwnsTerminalSessionParams{SessionID: sessionID, UserID: userID})
		if err != nil {
			return FileTransferDescriptor{}, err
		}
		if !owned {
			return FileTransferDescriptor{}, ErrTerminalSessionNotFound
		}
	}
	destination, err := s.db.Queries().GetUserMachineForUser(ctx, dbsqlc.GetUserMachineForUserParams{ID: destinationMachineID, UserID: userID})
	if errors.Is(err, sql.ErrNoRows) {
		return FileTransferDescriptor{}, ErrNotFound
	}
	if err != nil {
		return FileTransferDescriptor{}, err
	}
	if sessionID == "" && !slices.Contains(destination.ConfiguredCapabilities, "file_receive") {
		return FileTransferDescriptor{}, ErrMachineCapabilityUnavailable
	}
	if sessionID == "" && (!destination.Online || !slices.Contains(destination.ObservedCapabilities, "file_receive")) {
		return FileTransferDescriptor{}, ErrMachineOffline
	}
	if destination.State == "revoked" || destination.State == "disconnected" || destination.State == "deleted" {
		return FileTransferDescriptor{}, ErrNotFound
	}
	routeMachine := destination
	if sessionID != "" {
		host, hostErr := s.db.Queries().GetUserMachineTerminalSessionHostForUser(ctx, dbsqlc.GetUserMachineTerminalSessionHostForUserParams{SessionID: sessionID, UserID: userID})
		if hostErr == nil {
			routeMachine = host
		} else if !errors.Is(hostErr, sql.ErrNoRows) {
			return FileTransferDescriptor{}, hostErr
		}
	}
	if routeMachine.State == "revoked" || routeMachine.State == "disconnected" || routeMachine.State == "deleted" || sessionID != "" && !slices.Contains(routeMachine.ObservedCapabilities, "terminal_host") {
		return FileTransferDescriptor{}, ErrProvisioningUnavailable
	}
	route, err := s.db.Queries().GetActiveHelperRouteForEnvironment(ctx, routeMachine.EnvironmentID)
	if errors.Is(err, sql.ErrNoRows) {
		return FileTransferDescriptor{}, ErrProvisioningUnavailable
	}
	if err != nil {
		return FileTransferDescriptor{}, err
	}
	ttl := s.ttl
	if ttl <= 0 || ttl > 5*time.Minute {
		ttl = 5 * time.Minute
	}
	expiresAt := s.now().UTC().Add(ttl)
	jti := newID("jti_helper_file_transfer")
	token, err := s.controlSigner.SignCredential(mint.CredentialInput{
		Issuer: s.issuer, Audience: "paperboat-machine", Subject: userID, JTI: jti,
		IssuedAt: s.now().UTC(), ExpiresAt: expiresAt, CredentialClass: "file_transfer", Scopes: []string{"file:transfer"},
		EnvironmentID: routeMachine.EnvironmentID, MachineID: routeMachine.ID, SourceMachineID: sourceMachineID,
		UserID: userID, CLIClientSessionID: cliClientSessionID, SessionID: sessionID,
	})
	if err != nil {
		return FileTransferDescriptor{}, err
	}
	httpBaseURL := "https://" + route.PublicHost
	if err := s.db.Queries().CreateUserMachineAccessSession(ctx, dbsqlc.CreateUserMachineAccessSessionParams{
		ID: newID("umas"), UserMachineID: routeMachine.ID, UserID: userID, EnvironmentID: routeMachine.EnvironmentID,
		CLIClientSessionID: cliClientSessionID, HttpBaseUrl: httpBaseURL, HelperFileSessionID: jti, ExpiresAt: expiresAt,
	}); err != nil {
		return FileTransferDescriptor{}, err
	}
	return FileTransferDescriptor{
		Endpoint: httpBaseURL + "/v1/file-transfers", SourceMachineID: sourceMachineID,
		DestinationMachineID: destination.ID, InitiatingUserID: userID, Policy: s.fileTransferPolicy,
		Auth: map[string]any{"method": "bearer", "token": token, "expires_at": expiresAt, "scopes": []string{"file:transfer"}},
	}, nil
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
	response.Capabilities = []string{accessdescriptor.CapabilityTerminal, accessdescriptor.CapabilityFileTransfer, accessdescriptor.CapabilityPreview}
	response.Environment = map[string]any{"id": row.EnvironmentID, "kind": accessdescriptor.EnvironmentBYOD, "resource_id": row.ID, "display_name": row.DisplayName, "state": machineConnectionState(response.Connectable, row.State), "root": row.WorkspaceRoot}
}

func (s *Service) Connect(ctx context.Context, userID, sourceMachineID, userMachineID, cliClientSessionID string) (ConnectionDescriptor, error) {
	return s.ConnectTerminalSession(ctx, userID, sourceMachineID, userMachineID, cliClientSessionID, "")
}

func (s *Service) ConnectTerminalSession(ctx context.Context, userID, sourceMachineID, userMachineID, cliClientSessionID, terminalSessionID string) (ConnectionDescriptor, error) {
	if sourceMachineID == "" || sourceMachineID == userMachineID {
		return ConnectionDescriptor{}, ErrNotFound
	}
	if _, err := s.db.Queries().GetUserMachineForUser(ctx, dbsqlc.GetUserMachineForUserParams{ID: sourceMachineID, UserID: userID}); err != nil {
		return ConnectionDescriptor{}, ErrNotFound
	}
	row, err := s.db.Queries().GetUserMachineForUser(ctx, dbsqlc.GetUserMachineForUserParams{ID: userMachineID, UserID: userID})
	if errors.Is(err, sql.ErrNoRows) {
		return ConnectionDescriptor{}, ErrNotFound
	}
	if err != nil {
		return ConnectionDescriptor{}, err
	}
	if !slices.Contains(row.ConfiguredCapabilities, "terminal_host") {
		return ConnectionDescriptor{}, ErrMachineCapabilityUnavailable
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
	if row.State == "revoked" || row.State == "disconnected" || row.State == "deleted" {
		response.Status = "user_machine_revoked"
		response.Reason = "access_revoked"
		return response, nil
	}
	if !row.Online || !slices.Contains(row.ObservedCapabilities, "terminal_host") {
		response.Status, response.Reason = "machine_offline", "terminal_host_unavailable"
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
	input := access.CredentialInput{UserID: userID, ProjectID: row.ID, EnvironmentID: row.EnvironmentID, SourceMachineID: sourceMachineID, CLIClientSessionID: cliClientSessionID, HTTPBaseURL: httpBaseURL, ExpiresAt: expires}
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
	response.Terminal = map[string]any{"protocol": "paperboat.terminal.v1", "endpoints": machineTerminalEndpoints(websocketBaseURL), "session_id": terminalSession.ID, "thread_id": terminalSession.ThreadID, "terminal_id": terminalSession.TerminalID, "cwd": terminalSession.LaunchCwd, "auth": credentials.TerminalAuth}
	if credentials.FileTransferAuth != nil {
		response.FileTransfer = map[string]any{"endpoint": httpBaseURL + "/v1/file-transfers", "source_machine_id": sourceMachineID, "destination_machine_id": row.ID, "initiating_user_id": userID, "policy": s.fileTransferPolicy, "auth": credentials.FileTransferAuth}
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
			Issuer: s.issuer, Audience: "paperboat-machine", Subject: input.UserID, JTI: jti,
			IssuedAt: issuedAt, ExpiresAt: input.ExpiresAt, CredentialClass: class, Scopes: scopes,
			EnvironmentID: input.EnvironmentID, MachineID: input.ProjectID, SourceMachineID: input.SourceMachineID, UserID: input.UserID, CLIClientSessionID: input.CLIClientSessionID, SessionID: terminalSessionID,
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
	if strings.TrimSpace(sessionID) == "" {
		return dbsqlc.UserMachineTerminalSession{}, ErrTerminalSessionNotFound
	}
	row, err := s.db.Queries().GetUserMachineTerminalSession(ctx, dbsqlc.GetUserMachineTerminalSessionParams{ID: sessionID, UserMachineID: userMachineID, UserID: userID})
	if errors.Is(err, sql.ErrNoRows) {
		return dbsqlc.UserMachineTerminalSession{}, ErrTerminalSessionNotFound
	}
	return row, err
}

func (s *Service) Approve(ctx context.Context, userID, userCode string) (UserMachine, error) {
	return s.approve(ctx, userID, userCode, "host")
}

func (s *Service) approve(ctx context.Context, userID, userCode, setupMode string) (UserMachine, error) {
	if setupMode != "host" && setupMode != "receive" {
		return UserMachine{}, ErrInvalidPairing
	}
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
			if err := ensurePairingSSHTarget(ctx, tx, pairing, row); err != nil {
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
			if err != nil || row.State == "revoked" || row.State == "deleted" || row.SeatState != "released" && row.SeatState != "occupied" || row.Platform != pairing.Platform || row.Architecture != pairing.Architecture || row.WorkspaceRoot != pairing.WorkspaceRoot || row.DisplayName != pairing.RequestedDisplayName {
				return ErrEnrollmentState
			}
			if row.SeatState == "released" {
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
			}
			// A retry may come from a preserved machine record after local runtime
			// identity loss. Bind the pairing's authenticated key before issuing
			// material so the returned installation generation is authoritative.
			row, err = tx.Queries().BindCanonicalMachineIdentity(ctx, dbsqlc.BindCanonicalMachineIdentityParams{
				EnvironmentID:     row.EnvironmentID,
				PublicIdentityKey: sql.NullString{String: pairing.PublicIdentityKey, Valid: true},
				Now:               s.now().UTC(),
			})
			if err != nil {
				return err
			}
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
			if err := ensurePairingSSHTarget(ctx, tx, pairing, row); err != nil {
				return err
			}
			out, pairingID = mapMachine(row), pairing.ID
			return s.audit.WriteTx(ctx, tx, audit.Event{ActorUserID: userID, ActorType: audit.ActorUser, EventType: "user_machine.installation_retried", ResourceType: "user_machine", ResourceID: row.ID, IdempotencyKey: "user_machine.installation_retried:" + pairing.ID, Metadata: map[string]any{"environment_id": row.EnvironmentID, "generation": enrollment.Generation}})
		}
		if enrollmentErr == nil {
			existing, identityErr := tx.Queries().GetUserMachineByPublicIdentityForUpdate(ctx, sql.NullString{String: pairing.PublicIdentityKey, Valid: true})
			if identityErr == nil {
				if existing.UserID != userID {
					return ErrMachineIdentityConflict
				}
				if existing.Platform != pairing.Platform || existing.Architecture != pairing.Architecture || existing.WorkspaceRoot != pairing.WorkspaceRoot || existing.State == "revoked" || existing.State == "deleted" {
					return ErrEnrollmentState
				}
				if existing.SeatState == "released" {
					if s.seats == nil {
						return ErrSeatUnavailable
					}
					if err := s.seats.ReserveUserMachineSeat(ctx, tx, userID); err != nil {
						return err
					}
					if n, err := tx.Queries().OccupyUserMachineSeat(ctx, dbsqlc.OccupyUserMachineSeatParams{ID: existing.ID, UserID: userID}); err != nil || n != 1 {
						if err != nil {
							return err
						}
						return ErrEnrollmentState
					}
				} else if existing.SeatState != "occupied" {
					return ErrEnrollmentState
				}
				row, err := tx.Queries().AddUserMachineHostRole(ctx, dbsqlc.AddUserMachineHostRoleParams{ID: existing.ID, UserID: userID, DisplayName: pairing.RequestedDisplayName, WorkspaceRoot: pairing.WorkspaceRoot, RuntimeVersions: pairing.RuntimeVersions})
				if err != nil {
					return err
				}
				if setupMode == "receive" {
					row, err = tx.Queries().AddUserMachineInteractiveRole(ctx, dbsqlc.AddUserMachineInteractiveRoleParams{ID: existing.ID, UserID: userID, DisplayName: pairing.RequestedDisplayName, RuntimeVersions: pairing.RuntimeVersions, SetupMode: "receive", ConfiguredCapabilities: configuredCapabilities("receive")})
					if err != nil {
						return err
					}
				}
				if err := s.ensureHelperRoute(ctx, tx, row.ID, row.EnvironmentID); err != nil {
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
				if n, err := tx.Queries().ApproveUserMachineEnrollment(ctx, dbsqlc.ApproveUserMachineEnrollmentParams{UserMachineID: sql.NullString{String: row.ID, Valid: true}, PairingID: sql.NullString{String: pairing.ID, Valid: true}, UserID: userID}); err != nil || n != 1 {
					if err != nil {
						return err
					}
					return ErrEnrollmentState
				}
				if err := ensurePairingSSHTarget(ctx, tx, pairing, row); err != nil {
					return err
				}
				out, pairingID = mapMachine(row), pairing.ID
				return s.audit.WriteTx(ctx, tx, audit.Event{ActorUserID: userID, ActorType: audit.ActorUser, EventType: "user_machine.enrollment_restarted", ResourceType: "user_machine", ResourceID: row.ID, IdempotencyKey: "user_machine.enrollment_restarted:" + pairing.ID, Metadata: map[string]any{"environment_id": row.EnvironmentID, "generation": enrollment.Generation}})
			}
			if !errors.Is(identityErr, sql.ErrNoRows) {
				return identityErr
			}
			if s.seats == nil {
				return ErrSeatUnavailable
			}
			if err := s.seats.ReserveUserMachineSeat(ctx, tx, userID); err != nil {
				return err
			}
			environmentID := newID("env")
			alias, err := allocateMachineAlias(ctx, tx.Queries(), userID, pairing.RequestedDisplayName)
			if err != nil {
				return err
			}
			row, err := tx.Queries().CreateInteractiveMachine(ctx, dbsqlc.CreateInteractiveMachineParams{
				ID: newID("mch"), UserID: userID, EnvironmentID: environmentID, DisplayName: pairing.RequestedDisplayName, Alias: alias,
				Platform: pairing.Platform, Architecture: pairing.Architecture, WorkspaceRoot: pairing.WorkspaceRoot,
				RuntimeVersions: pairing.RuntimeVersions, SetupMode: "receive", ConfiguredCapabilities: configuredCapabilities("receive"),
				PublicIdentityKey: sql.NullString{String: pairing.PublicIdentityKey, Valid: true},
			})
			if userMachineTerminalSessionUniqueViolation(err) {
				return ErrMachineNameConflict
			}
			if err != nil {
				return err
			}
			if _, err := tx.Queries().CreateControlEnvironment(ctx, dbsqlc.CreateControlEnvironmentParams{ID: environmentID, WorkspaceID: row.ID, OwnerUserID: sql.NullString{String: userID, Valid: true}, DesiredState: "active"}); err != nil {
				return err
			}
			if n, err := tx.Queries().OccupyUserMachineSeat(ctx, dbsqlc.OccupyUserMachineSeatParams{ID: row.ID, UserID: userID}); err != nil || n != 1 {
				if err != nil {
					return err
				}
				return ErrEnrollmentState
			}
			row, err = tx.Queries().AddUserMachineHostRole(ctx, dbsqlc.AddUserMachineHostRoleParams{ID: row.ID, UserID: userID, DisplayName: pairing.RequestedDisplayName, WorkspaceRoot: pairing.WorkspaceRoot, RuntimeVersions: pairing.RuntimeVersions})
			if err != nil {
				return err
			}
			if setupMode == "receive" {
				row, err = tx.Queries().AddUserMachineInteractiveRole(ctx, dbsqlc.AddUserMachineInteractiveRoleParams{ID: row.ID, UserID: userID, DisplayName: pairing.RequestedDisplayName, RuntimeVersions: pairing.RuntimeVersions, SetupMode: "receive", ConfiguredCapabilities: configuredCapabilities("receive")})
				if err != nil {
					return err
				}
			}
			if err := s.ensureHelperRoute(ctx, tx, row.ID, row.EnvironmentID); err != nil {
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
			if n, err := tx.Queries().ApproveUserMachineEnrollment(ctx, dbsqlc.ApproveUserMachineEnrollmentParams{UserMachineID: sql.NullString{String: row.ID, Valid: true}, PairingID: sql.NullString{String: pairing.ID, Valid: true}, UserID: userID}); err != nil || n != 1 {
				if err != nil {
					return err
				}
				return ErrEnrollmentState
			}
			if err := ensurePairingSSHTarget(ctx, tx, pairing, row); err != nil {
				return err
			}
			out, pairingID = mapMachine(row), pairing.ID
			return s.audit.WriteTx(ctx, tx, audit.Event{ActorUserID: userID, ActorType: audit.ActorUser, EventType: "user_machine.enrollment_approved", ResourceType: "user_machine", ResourceID: row.ID, IdempotencyKey: "user_machine.enrollment_approved:" + pairing.ID, Metadata: map[string]any{"environment_id": row.EnvironmentID, "generation": enrollment.Generation}})
		}
		existing, identityErr := tx.Queries().GetUserMachineByPublicIdentityForUpdate(ctx, sql.NullString{String: pairing.PublicIdentityKey, Valid: true})
		if identityErr == nil {
			if existing.UserID != userID {
				return ErrMachineIdentityConflict
			}
			if existing.Platform != pairing.Platform || existing.Architecture != pairing.Architecture || existing.WorkspaceRoot != pairing.WorkspaceRoot {
				return ErrInvalidPairing
			}
			if existing.SeatState == "released" {
				if s.seats == nil {
					return ErrSeatUnavailable
				}
				if err := s.seats.ReserveUserMachineSeat(ctx, tx, userID); err != nil {
					return err
				}
				if n, err := tx.Queries().OccupyUserMachineSeat(ctx, dbsqlc.OccupyUserMachineSeatParams{ID: existing.ID, UserID: userID}); err != nil || n != 1 {
					if err != nil {
						return err
					}
					return ErrEnrollmentState
				}
			} else if existing.SeatState != "occupied" {
				return ErrEnrollmentState
			}
			row, err := tx.Queries().AddUserMachineHostRole(ctx, dbsqlc.AddUserMachineHostRoleParams{
				ID: existing.ID, UserID: userID, DisplayName: pairing.RequestedDisplayName,
				WorkspaceRoot: pairing.WorkspaceRoot, RuntimeVersions: pairing.RuntimeVersions,
			})
			if err != nil {
				return err
			}
			if setupMode == "receive" {
				row, err = tx.Queries().AddUserMachineInteractiveRole(ctx, dbsqlc.AddUserMachineInteractiveRoleParams{ID: existing.ID, UserID: userID, DisplayName: pairing.RequestedDisplayName, RuntimeVersions: pairing.RuntimeVersions, SetupMode: "receive", ConfiguredCapabilities: configuredCapabilities("receive")})
				if err != nil {
					return err
				}
			}
			if err := s.ensureHelperRoute(ctx, tx, row.ID, row.EnvironmentID); err != nil {
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
				if n, err := tx.Queries().ApproveUserMachineEnrollment(ctx, dbsqlc.ApproveUserMachineEnrollmentParams{UserMachineID: sql.NullString{String: row.ID, Valid: true}, PairingID: sql.NullString{String: pairing.ID, Valid: true}, UserID: userID}); err != nil || n != 1 {
					if err != nil {
						return err
					}
					return ErrEnrollmentState
				}
			}
			if err := ensurePairingSSHTarget(ctx, tx, pairing, row); err != nil {
				return err
			}
			out, pairingID = mapMachine(row), pairing.ID
			return s.audit.WriteTx(ctx, tx, audit.Event{ActorUserID: userID, ActorType: audit.ActorUser, EventType: "machine.host_role_added", ResourceType: "machine", ResourceID: row.ID, IdempotencyKey: "machine.host_role_added:" + pairing.ID})
		}
		if !errors.Is(identityErr, sql.ErrNoRows) {
			return identityErr
		}
		return ErrInvalidPairing
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

func ensurePairingSSHTarget(ctx context.Context, tx *db.Tx, pairing dbsqlc.UserMachinePairing, machine dbsqlc.UserMachine) error {
	if !pairing.SshUser.Valid && !pairing.SshPort.Valid {
		return nil
	}
	if !pairing.SshUser.Valid || !pairing.SshPort.Valid || !validPairingSSHUser(pairing.SshUser.String) || pairing.SshPort.Int32 < 1 || pairing.SshPort.Int32 > 65535 || machine.InstallationGeneration < 1 {
		return ErrInvalidPairing
	}
	return tx.Queries().UpsertPairingMachineSSHTarget(ctx, dbsqlc.UpsertPairingMachineSSHTargetParams{
		UserMachineID: machine.ID, MachineGeneration: machine.InstallationGeneration,
		OsUser: pairing.SshUser.String, TargetPort: pairing.SshPort.Int32,
	})
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
	if _, err := tx.Queries().ReactivateHelperRouteForEnvironment(ctx, dbsqlc.ReactivateHelperRouteForEnvironmentParams{EnvironmentID: environmentID, Now: s.now().UTC()}); err == nil {
		return nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	publicHost := strings.ReplaceAll(strings.ToLower(userMachineID), "_", "-") + "." + s.helperBaseDomain
	_, err := tx.Queries().CreateControlRoute(ctx, dbsqlc.CreateControlRouteParams{
		ID: newID("rte"), EnvironmentID: environmentID, ConnectorID: "runtime", Kind: "runtime_https_wss",
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
	artifact, ok := s.machineArtifact(machine.Platform, machine.Architecture)
	if !ok {
		return errors.New("user-machine artifact is unavailable")
	}
	pairing, err := s.db.Queries().GetUserMachinePairingByID(ctx, pairingID)
	if err != nil {
		return err
	}
	enrollment, err := s.db.Queries().GetUserMachineEnrollmentForPairingUpdate(ctx, sql.NullString{String: pairingID, Valid: true})
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	// Identity-based setup-to-pair requests do not create a legacy enrollment
	// row. The pairing itself remains the durable installation correlation.
	installationEnrollmentID := pairingID
	hasEnrollment := err == nil
	if err == nil {
		installationEnrollmentID = enrollment.ID
	}
	var grant HelperEnrollmentGrant
	reuseIdentity := false
	if existing, existingErr := s.db.Queries().GetActiveControlHelperForEnvironment(ctx, machine.EnvironmentID); existingErr == nil {
		if pairing.CanReuseRuntimeIdentity {
			grant = HelperEnrollmentGrant{HelperID: existing.ID, ExpiresAt: s.now().UTC().Add(10 * time.Minute)}
			reuseIdentity = true
		} else {
			if s.helperRecovery == nil {
				return ErrProvisioningUnavailable
			}
			grant, err = s.helperRecovery(ctx, userID, "byod-recovery:"+pairingID, machine.EnvironmentID, existing.ID, 10*time.Minute)
			if err != nil {
				return err
			}
		}
	} else if existingErr != nil && !errors.Is(existingErr, sql.ErrNoRows) {
		return existingErr
	} else {
		grant, err = s.helperGrant(ctx, userID, "byod-enrollment:"+pairingID, machine.EnvironmentID, 10*time.Minute)
		if err != nil {
			return err
		}
	}
	var cliSessionID, cliAccessToken, cliRefreshToken string
	if shouldIssueCLIEnrollmentSession(machine.SetupMode) && s.cliClientID != "" && s.cliScopes != "" && len(s.cliHashKey) > 0 && s.cliAccessLifetime > 0 && s.cliRefreshLifetime > 0 {
		cliSessionID = newID("cls")
		cliAccessToken, cliRefreshToken = oneShotToken(32), oneShotToken(32)
	}
	material, err := json.Marshal(map[string]any{
		"schema": "paperboat.byod-installation/v1", "user_machine_id": machine.ID, "user_machine_enrollment_id": installationEnrollmentID, "environment_id": machine.EnvironmentID,
		"control_url": s.issuer, "helper_id": grant.HelperID, "enrollment_id": grant.EnrollmentID,
		"enrollment_credential": grant.Credential, "reuse_identity": reuseIdentity, "expires_at": grant.ExpiresAt,
		"artifact":                artifact,
		"helper_listen_address":   fmt.Sprintf("127.0.0.1:%d", s.helperListenPort),
		"installation_generation": machine.InstallationGeneration,
		"setup_roles":             machine.SetupRoles,
		"setup_mode":              machine.SetupMode,
	})
	if cliSessionID != "" {
		var materialMap map[string]any
		if err := json.Unmarshal(material, &materialMap); err != nil {
			return err
		}
		materialMap["client_session"] = map[string]any{
			"schema": "paperboat.cli-session/v1", "session_id": cliSessionID,
			"access_token": cliAccessToken, "refresh_token": cliRefreshToken,
			"token_type": "Bearer", "expires_in": int(s.cliAccessLifetime / time.Second), "scope": s.cliScopes,
		}
		material, err = json.Marshal(materialMap)
	}
	if err != nil {
		return err
	}
	ciphertext, err := secrets.Encrypt(s.encryptionKey, string(material))
	if err != nil {
		return err
	}
	return s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		if cliSessionID != "" {
			now := s.now().UTC()
			if err := tx.Queries().CreateClientSession(ctx, dbsqlc.CreateClientSessionParams{ID: cliSessionID, UserID: userID, ClientID: s.cliClientID, ClientLabel: "Paperboat enrollment: " + machine.DisplayName, DeviceType: "desktop", Os: machine.Platform, Scopes: s.cliScopes, CreatedAt: now, ApprovedAt: now}); err != nil {
				return err
			}
			if err := tx.Queries().CreateClientAccessToken(ctx, dbsqlc.CreateClientAccessTokenParams{TokenHash: oneShotHash(s.cliHashKey, cliAccessToken), CLIClientSessionID: cliSessionID, ExpiresAt: now.Add(s.cliAccessLifetime), CreatedAt: now}); err != nil {
				return err
			}
			if err := tx.Queries().CreateClientRefreshToken(ctx, dbsqlc.CreateClientRefreshTokenParams{TokenHash: oneShotHash(s.cliHashKey, cliRefreshToken), CLIClientSessionID: cliSessionID, ExpiresAt: now.Add(s.cliRefreshLifetime), CreatedAt: now}); err != nil {
				return err
			}
		}
		n, err := tx.Queries().SetUserMachineInstallationConfig(ctx, dbsqlc.SetUserMachineInstallationConfigParams{ID: pairingID, Ciphertext: ciphertext})
		if err != nil {
			return err
		}
		if n != 1 {
			return ErrPairingUsed
		}
		if !hasEnrollment {
			return nil
		}
		_, err = tx.Queries().MarkUserMachineEnrollmentMaterialIssued(ctx, sql.NullString{String: pairingID, Valid: true})
		return err
	})
}

func shouldIssueCLIEnrollmentSession(setupMode string) bool {
	return strings.TrimSpace(setupMode) != "host"
}

func oneShotHash(key []byte, value string) string {
	m := hmac.New(sha256.New, key)
	_, _ = m.Write([]byte(value))
	return hex.EncodeToString(m.Sum(nil))
}

func oneShotToken(size int) string {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
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
	if requireActiveMachine && (machine.State != "online" || !slices.Contains(machine.ObservedCapabilities, "file_receive")) {
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

func (s *Service) Rename(ctx context.Context, userID, userMachineID, displayName string) (UserMachine, error) {
	userID, userMachineID, displayName = strings.TrimSpace(userID), strings.TrimSpace(userMachineID), strings.TrimSpace(displayName)
	if userID == "" || userMachineID == "" || invalidMachineDisplayName(displayName) {
		return UserMachine{}, ErrInvalidMachineName
	}
	var result UserMachine
	err := s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		row, err := tx.Queries().RenameUserMachine(ctx, dbsqlc.RenameUserMachineParams{DisplayName: displayName, ID: userMachineID, UserID: userID})
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if userMachineTerminalSessionUniqueViolation(err) {
			return ErrMachineNameConflict
		}
		if err != nil {
			return err
		}
		result = mapMachine(row)
		return s.audit.WriteTx(ctx, tx, audit.Event{ActorUserID: userID, ActorType: audit.ActorUser, EventType: "user_machine.renamed", ResourceType: "user_machine", ResourceID: userMachineID, IdempotencyKey: "user_machine.renamed:" + userMachineID + ":" + strconv.FormatInt(row.Version, 10), Metadata: map[string]any{"display_name": displayName, "version": row.Version}})
	})
	return result, err
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
	requestedName := strings.ToLower(strings.TrimSpace(name))
	if requestedName != "" && !validUserMachineTerminalSessionName(requestedName) {
		return TerminalSession{}, ErrTerminalSessionInvalidName
	}
	if strings.TrimSpace(idempotencyKey) == "" {
		return TerminalSession{}, ErrTerminalSessionIdempotency
	}
	if maxActive <= 0 {
		return TerminalSession{}, ErrTerminalSessionLimit
	}
	if existing, err := s.db.Queries().GetUserMachineTerminalSessionByIdempotencyKey(ctx, dbsqlc.GetUserMachineTerminalSessionByIdempotencyKeyParams{UserMachineID: userMachineID, UserID: userID, IdempotencyKey: sql.NullString{String: idempotencyKey, Valid: true}}); err == nil {
		return mapTerminalSession(existing), nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return TerminalSession{}, err
	}
	id, terminalID := newID("umts"), newID("term")
	var evictedSession *TerminalSession
	err := s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		_, err := tx.Queries().LockUserMachineTerminalSessions(ctx, dbsqlc.LockUserMachineTerminalSessionsParams{UserMachineID: userMachineID, UserID: userID})
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		lockedMachine, err := tx.Queries().GetUserMachineForUser(ctx, dbsqlc.GetUserMachineForUserParams{ID: userMachineID, UserID: userID})
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		if err := terminalHostAvailability(lockedMachine); err != nil {
			return err
		}
		if existing, err := tx.Queries().GetUserMachineTerminalSessionByIdempotencyKey(ctx, dbsqlc.GetUserMachineTerminalSessionByIdempotencyKeyParams{UserMachineID: userMachineID, UserID: userID, IdempotencyKey: sql.NullString{String: idempotencyKey, Valid: true}}); err == nil {
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
		}
		for attempts := 0; attempts < 32; attempts++ {
			if requestedName == "" {
				sessionName = naming.Session(ordinal)
			}
			created, createErr := tx.Queries().CreateUserMachineTerminalSession(ctx, dbsqlc.CreateUserMachineTerminalSessionParams{ID: id, UserMachineID: userMachineID, TerminalID: terminalID, Name: sessionName, AutoNameOrdinal: ordinal, IdempotencyKey: sql.NullString{String: idempotencyKey, Valid: true}, LaunchCwd: lockedMachine.WorkspaceRoot})
			if createErr != nil {
				return createErr
			}
			if created > 0 {
				return nil
			}
			if requestedName != "" {
				return ErrTerminalSessionConflict
			}
			ordinal++
		}
		return ErrTerminalSessionConflict
	})
	if err != nil {
		if userMachineTerminalSessionUniqueViolation(err) {
			existing, lookupErr := s.db.Queries().GetUserMachineTerminalSessionByIdempotencyKey(ctx, dbsqlc.GetUserMachineTerminalSessionByIdempotencyKeyParams{UserMachineID: userMachineID, UserID: userID, IdempotencyKey: sql.NullString{String: idempotencyKey, Valid: true}})
			if lookupErr == nil {
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

func terminalHostAvailability(machine dbsqlc.UserMachine) error {
	if !slices.Contains(machine.ConfiguredCapabilities, "terminal_host") {
		return ErrMachineCapabilityUnavailable
	}
	if !machine.Online || !slices.Contains(machine.ObservedCapabilities, "terminal_host") {
		return ErrMachineOffline
	}
	return nil
}

func userMachineTerminalSessionUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

func (s *Service) CreateConfiguredTerminalSession(ctx context.Context, userID, userMachineID, name, idempotencyKey string) (TerminalSession, error) {
	return s.CreateTerminalSession(ctx, userID, userMachineID, name, idempotencyKey, s.maxSessions)
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
	return name != "default" && terminalSessionNamePattern.MatchString(name)
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
		Issuer: s.issuer, Audience: "paperboat-machine", Subject: userID, JTI: newID("jti"),
		IssuedAt: now, ExpiresAt: now.Add(mint.MaxProofTTL), CredentialClass: "terminal_operation", Scopes: []string{"terminal:operate"},
		EnvironmentID: environmentID, MachineID: userMachineID, UserID: userID, CLIClientSessionID: operationID, SessionID: terminalSessionID,
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
	session := TerminalSession{ID: row.ID, Name: row.Name, IsDefault: row.IsDefault, State: row.DesiredState, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt}
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

func (s *Service) Unpair(ctx context.Context, userID, machineID string) (UserMachine, error) {
	userID, machineID = strings.TrimSpace(userID), strings.TrimSpace(machineID)
	if userID == "" || machineID == "" {
		return UserMachine{}, ErrNotFound
	}
	var result UserMachine
	err := s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		machine, err := tx.Queries().GetUserMachineForUpdate(ctx, dbsqlc.GetUserMachineForUpdateParams{ID: machineID, UserID: userID})
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if !slices.Contains(machine.SetupRoles, "host") {
			result = mapMachine(machine)
			return nil
		}
		machine, err = tx.Queries().RemoveUserMachineHostRole(ctx, dbsqlc.RemoveUserMachineHostRoleParams{ID: machineID, UserID: userID})
		if err != nil {
			return err
		}
		if err := s.revokeHostAuthorityTx(ctx, tx, machine.ID, machine.EnvironmentID, s.now().UTC()); err != nil {
			return err
		}
		result = mapMachine(machine)
		return s.audit.WriteTx(ctx, tx, audit.Event{ActorUserID: userID, ActorType: audit.ActorUser, EventType: "machine.host_role_removed", ResourceType: "machine", ResourceID: machineID, IdempotencyKey: "machine.host_role_removed:" + machineID + ":" + strconv.FormatInt(machine.InstallationGeneration, 10)})
	})
	if err != nil {
		return UserMachine{}, err
	}
	return result, s.RevokeUserMachineSessions(ctx, machineID, "machine_unpaired")
}

func (s *Service) revokeHostAuthorityTx(ctx context.Context, tx *db.Tx, machineID, environmentID string, now time.Time) error {
	if _, err := tx.Queries().StopCodexSessionsForMachine(ctx, dbsqlc.StopCodexSessionsForMachineParams{MachineID: machineID, Now: sql.NullTime{Time: now, Valid: true}}); err != nil {
		return err
	}
	if _, err := tx.Queries().RevokeControlConfigCredentialsForEnvironment(ctx, dbsqlc.RevokeControlConfigCredentialsForEnvironmentParams{EnvironmentID: environmentID, RevokedAt: sql.NullTime{Time: now, Valid: true}}); err != nil {
		return err
	}
	if _, err := tx.Queries().RevokeControlConfigRepositoryAccessForEnvironment(ctx, dbsqlc.RevokeControlConfigRepositoryAccessForEnvironmentParams{EnvironmentID: environmentID, Now: now}); err != nil {
		return err
	}
	_, err := tx.Queries().RevokeControlConfigRepositoryLeasesForEnvironment(ctx, dbsqlc.RevokeControlConfigRepositoryLeasesForEnvironmentParams{EnvironmentID: sql.NullString{String: environmentID, Valid: true}, Now: sql.NullTime{Time: now, Valid: true}})
	return err
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
	_, validWorkspace := canonicalWorkspaceRoot(in.Platform, in.WorkspaceRoot)
	publicKey, keyErr := base64.RawURLEncoding.DecodeString(strings.TrimSpace(in.PublicIdentityKey))
	checks := []struct {
		invalid bool
		reason  string
	}{
		{s.policy.PairingLifetime <= 0, "pairing lifetime"},
		{strings.TrimSpace(in.Verifier) == "", "verifier"},
		{invalidMachineDisplayName(in.DisplayName), "display name"},
		{!validMachineArchitecture(in.Architecture), "architecture"},
		{!validWorkspace, "workspace root"},
		{!slices.Contains(s.policy.AllowedPlatforms, strings.ToLower(strings.TrimSpace(in.Platform))), "platform"},
		{isUnacceptedBetaPlatform(in.Platform, in.Architecture, in.AcceptBetaPlatform), "beta acceptance"},
		{token != "" && !validEnrollmentToken(token), "enrollment token shape"},
		{keyErr != nil || len(publicKey) != ed25519.PublicKeySize, "public identity key"},
		{(in.SSHUser == "") != (in.SSHPort == 0), "SSH target completeness"},
		{in.SSHUser != "" && !validPairingSSHUser(in.SSHUser), "SSH user"},
	}
	for _, check := range checks {
		if check.invalid {
			return fmt.Errorf("%w: %s", ErrInvalidPairing, check.reason)
		}
	}
	return nil
}

// Display names historically allowed spaces for friendly UI labels, but they
// must never accept command-line fragments or path/control characters. The
// enrollment client applies the stricter portable hostname-label contract;
// this server-side guard protects older clients and direct API callers too.
func invalidMachineDisplayName(value string) bool {
	value = strings.TrimSpace(value)
	return value == "" || utf8.RuneCountInString(value) > 128 || strings.HasPrefix(value, "-") || strings.ContainsAny(value, "=\\/\x00\r\n")
}

func validPairingSSHUser(value string) bool {
	if value == "" || len(value) > 128 || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\x00\r\n@") {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func canonicalWorkspaceRoot(platform, root string) (string, bool) {
	if strings.ContainsRune(root, '\x00') || strings.TrimSpace(root) != root || root == "" {
		return "", false
	}
	if !strings.EqualFold(strings.TrimSpace(platform), "windows") {
		return root, filepath.IsAbs(root) && filepath.Clean(root) == root
	}
	root = strings.ReplaceAll(root, "/", `\`)
	prefix, remainder := "", root
	switch {
	case len(root) >= 3 && ((root[0] >= 'A' && root[0] <= 'Z') || (root[0] >= 'a' && root[0] <= 'z')) && root[1] == ':' && root[2] == '\\':
		prefix, remainder = strings.ToUpper(root[:1])+root[1:3], root[3:]
	case strings.HasPrefix(root, `\\`):
		parts := strings.Split(root[2:], `\`)
		if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
			return "", false
		}
		prefix = `\\` + parts[0] + `\` + parts[1]
		remainder = strings.Join(parts[2:], `\`)
	default:
		return "", false
	}
	segments := strings.Split(remainder, `\`)
	clean := make([]string, 0, len(segments))
	for _, segment := range segments {
		if segment == "" {
			continue
		}
		if segment == "." || segment == ".." || strings.ContainsAny(segment, `<>:"|?*`) {
			return "", false
		}
		clean = append(clean, segment)
	}
	if len(clean) == 0 {
		return prefix, true
	}
	separator := `\`
	if strings.HasSuffix(prefix, `\`) {
		separator = ""
	}
	canonical := prefix + separator + strings.Join(clean, `\`)
	return canonical, canonical == root
}

func validMachineArchitecture(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	return value == "amd64" || value == "arm64"
}

func isUnacceptedBetaPlatform(platform, architecture string, accepted bool) bool {
	return strings.EqualFold(strings.TrimSpace(platform), "windows") && strings.EqualFold(strings.TrimSpace(architecture), "arm64") && !accepted
}
func mapMachine(row dbsqlc.UserMachine) UserMachine {
	diagnostics := RuntimeDiagnostics{WorkerGeneration: uint64(row.WorkerGeneration), OSBootID: row.OsBootID.String, WorkerServiceScope: row.WorkerServiceScope, ConnectorState: row.ConnectorState, ConnectorGeneration: uint64(row.ConnectorGeneration)}
	if row.RuntimeDiagnosticsObservedAt.Valid {
		observed := row.RuntimeDiagnosticsObservedAt.Time
		diagnostics.ObservedAt = &observed
	}
	m := UserMachine{ID: row.ID, EnvironmentID: row.EnvironmentID, DisplayName: row.DisplayName, Alias: row.Alias, Platform: row.Platform, Architecture: row.Architecture, WorkspaceRoot: row.WorkspaceRoot, State: row.State, SeatState: row.SeatState, Online: row.Online, RuntimeVersions: row.RuntimeVersions, SetupRoles: append([]string(nil), row.SetupRoles...), SetupMode: row.SetupMode, Capabilities: mapCapabilities(row.ConfiguredCapabilities, row.ObservedCapabilities), MachineKind: row.MachineKind, PublicIdentityKey: row.PublicIdentityKey.String, InstallationGeneration: row.InstallationGeneration, Availability: mapAvailability(row), RuntimeDiagnostics: diagnostics}
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

func allocateMachineAlias(ctx context.Context, queries *dbsqlc.Queries, userID, displayName string) (string, error) {
	if err := queries.LockUserMachineAliases(ctx, userID); err != nil {
		return "", err
	}
	for ordinal := 1; ordinal <= 10_000; ordinal++ {
		candidate := machinealias.Candidate(displayName, ordinal)
		exists, err := queries.UserMachineAliasExists(ctx, dbsqlc.UserMachineAliasExistsParams{UserID: userID, Alias: candidate})
		if err != nil {
			return "", err
		}
		if !exists {
			return candidate, nil
		}
	}
	return "", ErrMachineNameConflict
}

func mapCapabilities(configured, observed []string) MachineCapabilities {
	capability := func(name string) CapabilityAvailability {
		return CapabilityAvailability{Configured: slices.Contains(configured, name), Observed: slices.Contains(observed, name)}
	}
	return MachineCapabilities{FileReceive: capability("file_receive"), PreviewLaunch: capability("preview_launch"), TerminalHost: capability("terminal_host"), CodexHost: capability("codex_host"), SessionHost: capability("session_host"), KeepAwake: capability("keep_awake")}
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

const enrollmentTokenLength = 26

func validEnrollmentToken(token string) bool {
	_, ok := enrollmentTokenSecret(strings.TrimSpace(token))
	return ok
}

func enrollmentTokenSecret(token string) (string, bool) {
	token = strings.TrimSpace(token)
	if len(token) != enrollmentTokenLength {
		return "", false
	}
	for i := range token {
		if !((token[i] >= '0' && token[i] <= '9') || (token[i] >= 'A' && token[i] <= 'Z')) {
			return "", false
		}
	}
	return token[2:], true
}

func enrollmentTokenHash(token string) [sha256.Size]byte {
	secret, _ := enrollmentTokenSecret(token)
	return sha256.Sum256([]byte(secret))
}

// randomEnrollmentToken returns one URL-safe credential. The first character
// carries role parity, the second carries shell parity, and the remaining
// characters carry the secret entropy.
func randomEnrollmentToken() (string, error) {
	const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	metadata, err := randomCodeFromAlphabet(alphabet, 2)
	if err != nil {
		return "", err
	}
	rest, err := randomCodeFromAlphabet(alphabet, enrollmentTokenLength-2)
	if err != nil {
		return "", err
	}
	return metadata + rest, nil
}

func randomEnrollmentTokenFor(role, shell string) (string, error) {
	role = strings.ToLower(strings.TrimSpace(role))
	shell = strings.ToLower(strings.TrimSpace(shell))
	if role != "host" && role != "client" {
		return "", errors.New("enrollment role must be host or client")
	}
	if shell != "posix" && shell != "powershell" {
		return "", errors.New("enrollment shell is invalid")
	}
	roleEven, shellEven := role == "host", shell == "posix"
	metadata := make([]byte, 2)
	for i, even := range []bool{roleEven, shellEven} {
		chars := "13579ACEGIKMOQSUWY"
		if even {
			chars = "02468BDFHJLNPRTVXZ"
		}
		value, err := randomCodeFromAlphabet(chars, 1)
		if err != nil {
			return "", err
		}
		metadata[i] = value[0]
	}
	rest, err := randomCodeFromAlphabet("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ", enrollmentTokenLength-2)
	if err != nil {
		return "", err
	}
	return string(metadata) + rest, nil
}

func randomCodeFromAlphabet(alphabet string, length int) (string, error) {
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
