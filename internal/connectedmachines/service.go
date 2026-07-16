package connectedmachines

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/agentunnel"
	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
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
	ErrInstallationUnavailable    = errors.New("connected-machine installation material is unavailable")
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
	AllowedPlatforms []string
}
type Service struct {
	db               *db.DB
	audit            *audit.Writer
	policy           Policy
	seats            SeatAuthorizer
	now              func() time.Time
	provisioner      agentunnel.Client
	encryptionKey    string
	credentials      agentunnel.CredentialIssuer
	issuer           string
	ttl              time.Duration
	uploadMaxBytes   int64
	uploadMIMEs      []string
	uploadRetention  int64
	maxSessions      int
	controlSigner    *mint.Provider
	controlHTTP      *http.Client
	bootstrapCommand string
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
	s.controlHTTP = client
}

func (s *Service) ConfigureBootstrapCommand(command string) {
	s.bootstrapCommand = strings.TrimSpace(command)
}

func New(store *db.DB, auditWriter *audit.Writer, policy Policy, seats SeatAuthorizer) *Service {
	return &Service{db: store, audit: auditWriter, policy: policy, seats: seats, now: time.Now, maxSessions: 32}
}

type PairingInput struct {
	Verifier, DisplayName, Platform, Architecture, WorkspaceRoot string
	RuntimeVersions                                              json.RawMessage
}
type Pairing struct {
	ID, UserCode string
	ExpiresAt    time.Time
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
	row, err := s.db.Queries().CreateConnectedMachinePairing(ctx, dbsqlc.CreateConnectedMachinePairingParams{ID: newID("cmp"), VerifierHash: verifierHash[:], UserCode: code, RequestedDisplayName: strings.TrimSpace(in.DisplayName), Platform: strings.ToLower(strings.TrimSpace(in.Platform)), Architecture: strings.ToLower(strings.TrimSpace(in.Architecture)), WorkspaceRoot: filepath.Clean(in.WorkspaceRoot), RuntimeVersions: in.RuntimeVersions, ExpiresAt: expires})
	if err != nil {
		return Pairing{}, err
	}
	return Pairing{ID: row.ID, UserCode: row.UserCode, ExpiresAt: row.ExpiresAt}, nil
}

type Machine struct {
	ID, EnvironmentID, DisplayName, Platform, Architecture, WorkspaceRoot, State, SeatState string
	Online                                                                                  bool
	RuntimeVersions                                                                         json.RawMessage
	EnrolledAt, LastSeenAt                                                                  *time.Time
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
	if available < 0 {
		available = 0
	}
	return Overview{
		EntitlementState: entitlement.State, ProductCode: entitlement.ProductCode,
		PeriodStart: entitlement.CurrentPeriodStart, PeriodEnd: entitlement.CurrentPeriodEnd,
		SeatQuantity: entitlement.SeatQuantity, OccupiedSeats: occupied, AvailableSeats: available,
		IncludedBytes: usage.IncludedBytes, ConsumedIncluded: usage.ConsumedIncludedBytes,
		ConsumedTopup: usage.ConsumedTopupBytes, TopupRemaining: usage.PaidTopupRemainingBytes,
		BootstrapCommand: s.bootstrapCommand,
	}, nil
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
	expires := s.now().UTC().Add(ttl)
	response := ConnectResponse{Issuer: s.issuer, ConnectedMachineID: row.ID, ConnectedMachineState: row.State, ExpiresAt: expires, Status: "connector_connecting", Reason: "connector_offline", RetryAfterSeconds: 2}
	if row.State == "revoked" || row.State == "disconnected" || row.State == "deleted" || row.SeatState != "occupied" {
		response.Status = "connected_machine_revoked"
		response.Reason = "access_revoked"
		return response, nil
	}
	if !row.AgentunnelHttpBaseUrl.Valid || !row.AgentunnelWebsocketBaseUrl.Valid || s.provisioner == nil {
		return response, nil
	}
	status, statusErr := s.provisioner.Status(ctx, agentunnel.ResourceDescriptor{TunnelID: row.AgentunnelRouteID.String, ClientID: row.AgentunnelClientID.String, HTTPBaseURL: row.AgentunnelHttpBaseUrl.String, WebSocketBaseURL: row.AgentunnelWebsocketBaseUrl.String})
	if statusErr != nil || !status.Ready {
		response.Status, response.Reason = "connector_connecting", "tunnel_offline"
		return response, nil
	}
	if s.credentials == nil || clientSessionID == "" {
		return ConnectResponse{}, errors.New("connected-machine credential issuer is unavailable")
	}
	input := agentunnel.CredentialInput{UserID: userID, ProjectID: row.ID, EnvironmentID: row.EnvironmentID, ClientSessionID: clientSessionID, HTTPBaseURL: row.AgentunnelHttpBaseUrl.String, ExpiresAt: expires}
	if err := s.credentials.CheckCLI(ctx, input); err != nil {
		return ConnectResponse{}, err
	}
	if checker, ok := s.credentials.(interface {
		CheckHealth(context.Context, agentunnel.CredentialInput) error
	}); ok {
		if err := checker.CheckHealth(ctx, input); err != nil {
			response.Status = "papercode_starting"
			response.Reason = "papercode_unhealthy"
			return response, nil
		}
	}
	if err := s.ApplyTerminalSessionOperations(ctx, row.ID); err != nil {
		response.Status = "papercode_starting"
		response.Reason = "terminal_session_operation_pending"
		return response, nil
	}
	credentials, err := s.credentials.IssueCLI(ctx, input)
	if err != nil {
		return ConnectResponse{}, err
	}
	if len(compactSessionIDs(credentials.TerminalSessionID, credentials.FileSessionID)) == 0 {
		return ConnectResponse{}, errors.New("connected-machine credential issuer returned no revocable sessions")
	}
	if err := s.db.Queries().CreateConnectedMachineAccessSession(ctx, dbsqlc.CreateConnectedMachineAccessSessionParams{
		ID: newID("cmas"), ConnectedMachineID: row.ID, UserID: userID, EnvironmentID: row.EnvironmentID,
		ClientSessionID: clientSessionID, HttpBaseUrl: row.AgentunnelHttpBaseUrl.String,
		PapercodeTerminalSessionID: credentials.TerminalSessionID, PapercodeFileSessionID: credentials.FileSessionID,
		ExpiresAt: expires,
	}); err != nil {
		cleanupErr := s.revokeCredentialSessions(ctx, machineAccessSession{
			UserID: userID, ConnectedMachineID: row.ID, EnvironmentID: row.EnvironmentID,
			ClientSessionID: clientSessionID, HTTPBaseURL: row.AgentunnelHttpBaseUrl.String,
			TerminalSessionID: credentials.TerminalSessionID, FileSessionID: credentials.FileSessionID,
		}, "access_session_persistence_failed")
		return ConnectResponse{}, errors.Join(err, cleanupErr)
	}
	response.Connectable, response.Status, response.Reason, response.RetryAfterSeconds = true, "ready", "ready", 0
	response.Environment = map[string]any{"environment_id": row.EnvironmentID, "connected_machine_id": row.ID, "display_name": row.DisplayName, "project_root": row.WorkspaceRoot}
	response.Terminal = map[string]any{"kind": "papercode_websocket", "http_base_url": row.AgentunnelHttpBaseUrl.String, "websocket_base_url": row.AgentunnelWebsocketBaseUrl.String, "thread_id": terminalSession.ThreadID, "terminal_id": terminalSession.TerminalID, "cwd": terminalSession.LaunchCwd, "auth": credentials.TerminalAuth}
	response.Upload = map[string]any{"kind": "papercode_staged_image", "http_base_url": row.AgentunnelHttpBaseUrl.String, "path": "/api/files/staged-images", "max_bytes": s.uploadMaxBytes, "allowed_mime_types": s.uploadMIMEs, "retention_seconds": s.uploadRetention, "auth": credentials.UploadAuth}
	return response, nil
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
	if row.State == "revoked" || row.State == "disconnected" || row.State == "deleted" || row.SeatState != "occupied" {
		response.Status = "connected_machine_revoked"
		response.Reason = "access_revoked"
		return response, nil
	}
	if !row.AgentunnelHttpBaseUrl.Valid || !row.AgentunnelWebsocketBaseUrl.Valid || s.provisioner == nil {
		return response, nil
	}
	status, statusErr := s.provisioner.Status(ctx, agentunnel.ResourceDescriptor{TunnelID: row.AgentunnelRouteID.String, ClientID: row.AgentunnelClientID.String, HTTPBaseURL: row.AgentunnelHttpBaseUrl.String, WebSocketBaseURL: row.AgentunnelWebsocketBaseUrl.String})
	if statusErr != nil || !status.Ready {
		response.Reason = "tunnel_offline"
		return response, nil
	}
	response.Connectable, response.Status, response.Reason, response.RetryAfterSeconds = true, "ready", "ready", 0
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
	if s.seats == nil {
		return Machine{}, ErrSeatUnavailable
	}
	var out Machine
	var pairingID string
	err := s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		pairing, err := tx.Queries().GetConnectedMachinePairingForCode(ctx, strings.TrimSpace(userCode))
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
			_, _ = tx.Queries().ExpireConnectedMachinePairing(ctx, pairing.ID)
			return ErrPairingExpired
		}
		if err := s.seats.ReserveConnectedMachineSeat(ctx, tx, userID); err != nil {
			return err
		}
		row, err := tx.Queries().CreateConnectedMachine(ctx, dbsqlc.CreateConnectedMachineParams{ID: newID("cm"), UserID: userID, EnvironmentID: newID("env"), DisplayName: pairing.RequestedDisplayName, Platform: pairing.Platform, Architecture: pairing.Architecture, WorkspaceRoot: pairing.WorkspaceRoot, RuntimeVersions: pairing.RuntimeVersions})
		if err != nil {
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
		out = mapMachine(row)
		pairingID = pairing.ID
		return s.audit.WriteTx(ctx, tx, audit.Event{ActorUserID: userID, ActorType: audit.ActorUser, EventType: "connected_machine.approved", ResourceType: "connected_machine", ResourceID: row.ID, IdempotencyKey: "connected_machine.approved:" + pairing.ID, Metadata: map[string]any{"platform": row.Platform, "architecture": row.Architecture}})
	})
	if err != nil || s.provisioner == nil {
		return out, err
	}
	if err := s.provisionApprovedMachine(ctx, userID, pairingID, out); err != nil {
		return Machine{}, err
	}
	return out, nil
}

func (s *Service) provisionApprovedMachine(ctx context.Context, userID, pairingID string, machine Machine) error {
	if strings.TrimSpace(s.encryptionKey) == "" {
		return errors.New("connected-machine provisioning encryption is not configured")
	}
	resource, err := s.provisioner.EnsureProjectResources(ctx, agentunnel.ProjectRef{ID: machine.ID, Name: machine.DisplayName})
	if err != nil {
		return err
	}
	material, err := json.Marshal(map[string]any{"machine_id": machine.ID, "environment_id": machine.EnvironmentID, "agentunnel_client_id": resource.ClientID, "agentunnel_route_id": resource.TunnelID, "agentunnel_token": resource.MachineToken, "http_base_url": resource.HTTPBaseURL, "websocket_base_url": resource.WebSocketBaseURL})
	if err != nil {
		return err
	}
	ciphertext, err := secrets.Encrypt(s.encryptionKey, string(material))
	if err != nil {
		return err
	}
	return s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		if n, err := tx.Queries().SetConnectedMachineRoute(ctx, dbsqlc.SetConnectedMachineRouteParams{ID: machine.ID, UserID: userID, AgentunnelRouteID: sql.NullString{String: resource.TunnelID, Valid: resource.TunnelID != ""}, AgentunnelClientID: sql.NullString{String: resource.ClientID, Valid: resource.ClientID != ""}, AgentunnelHttpBaseUrl: sql.NullString{String: resource.HTTPBaseURL, Valid: resource.HTTPBaseURL != ""}, AgentunnelWebsocketBaseUrl: sql.NullString{String: resource.WebSocketBaseURL, Valid: resource.WebSocketBaseURL != ""}}); err != nil || n != 1 {
			if err != nil {
				return err
			}
			return ErrNotFound
		}
		if n, err := tx.Queries().SetConnectedMachineInstallationConfig(ctx, dbsqlc.SetConnectedMachineInstallationConfigParams{ID: pairingID, Ciphertext: ciphertext}); err != nil || n != 1 {
			if err != nil {
				return err
			}
			return ErrPairingUsed
		}
		return nil
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
		if machine.State != "online" || machine.SeatState != "occupied" {
			return ErrBandwidthDenied
		}
		period, err := s.ensureCurrentBandwidthPeriod(ctx, tx, machine)
		if err != nil {
			return err
		}
		remaining := requestedBytes
		includedAvailable := period.IncludedBytes - period.ConsumedIncludedBytes
		if includedAvailable > 0 {
			consume := minInt64(remaining, includedAvailable)
			rows, err := tx.Queries().ConsumeConnectedMachineIncludedBandwidth(ctx, dbsqlc.ConsumeConnectedMachineIncludedBandwidthParams{ID: period.ID, Bytes: consume})
			if err != nil {
				return err
			}
			if rows != 1 {
				return ErrBandwidthDenied
			}
			remaining -= consume
			reservation.GrantedBytes += consume
		}
		if remaining > 0 {
			topups, err := tx.Queries().ListActiveConnectedMachineTopupsForUpdate(ctx, machine.UserID)
			if err != nil {
				return err
			}
			for _, topup := range topups {
				if remaining == 0 {
					break
				}
				consume := minInt64(remaining, topup.RemainingBytes)
				rows, err := tx.Queries().ConsumeConnectedMachineTopup(ctx, dbsqlc.ConsumeConnectedMachineTopupParams{ID: topup.ID, Bytes: consume})
				if err != nil {
					return err
				}
				if rows != 1 {
					return ErrBandwidthDenied
				}
				remaining -= consume
				reservation.GrantedBytes += consume
			}
		}
		if reservation.GrantedBytes > 0 {
			rows, err := tx.Queries().RecordConnectedMachineTopupConsumption(ctx, dbsqlc.RecordConnectedMachineTopupConsumptionParams{ID: period.ID, Bytes: reservation.GrantedBytes - minInt64(reservation.GrantedBytes, includedAvailable)})
			if err != nil {
				return err
			}
			if rows != 1 {
				return ErrBandwidthDenied
			}
		}
		reservation.Exhausted = remaining > 0
		return nil
	})
	return reservation, err
}

func (s *Service) ReserveBandwidthForRoute(ctx context.Context, routeID string, requestedBytes int64) (BandwidthReservation, error) {
	machineID, err := s.db.Queries().GetConnectedMachineIDForRoute(ctx, sql.NullString{String: strings.TrimSpace(routeID), Valid: strings.TrimSpace(routeID) != ""})
	if errors.Is(err, sql.ErrNoRows) {
		return BandwidthReservation{}, ErrNotFound
	}
	if err != nil {
		return BandwidthReservation{}, err
	}
	return s.ReserveBandwidth(ctx, machineID, requestedBytes)
}

func (s *Service) ensureCurrentBandwidthPeriod(ctx context.Context, tx *db.Tx, machine dbsqlc.ConnectedMachine) (dbsqlc.ConnectedMachineBandwidthPeriod, error) {
	entitlement, err := tx.Queries().GetConnectedMachineEntitlementForUpdate(ctx, machine.UserID)
	if errors.Is(err, sql.ErrNoRows) {
		return dbsqlc.ConnectedMachineBandwidthPeriod{}, ErrBandwidthDenied
	}
	if err != nil {
		return dbsqlc.ConnectedMachineBandwidthPeriod{}, err
	}
	now := s.now().UTC()
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
	for {
		items, err := s.db.Queries().ListPendingConnectedMachineTerminalSessionOperations(ctx, dbsqlc.ListPendingConnectedMachineTerminalSessionOperationsParams{ConnectedMachineID: machineID, BatchSize: 32})
		if err != nil {
			return err
		}
		if len(items) == 0 {
			return nil
		}
		for _, item := range items {
			if err := s.applyTerminalSessionOperation(ctx, item.ID, item.ConnectedMachineID, item.Operation, item.Attempts, item.UserID, item.EnvironmentID, item.AgentunnelHttpBaseUrl, item.ThreadID, item.TerminalID); err != nil {
				return err
			}
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
		if err := s.applyTerminalSessionOperation(ctx, item.ID, item.ConnectedMachineID, item.Operation, item.Attempts, item.UserID, item.EnvironmentID, item.AgentunnelHttpBaseUrl, item.ThreadID, item.TerminalID); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (s *Service) applyTerminalSessionOperation(ctx context.Context, operationID, machineID, operation string, attempts int32, userID, environmentID string, route sql.NullString, threadID, terminalID string) error {
	if s.controlSigner == nil || s.controlHTTP == nil || !route.Valid || strings.TrimSpace(s.issuer) == "" {
		return s.retryTerminalSessionOperation(ctx, operationID, attempts, errors.New("connected-machine terminal control is unavailable"))
	}
	proof, err := s.controlSigner.SignTerminalControl(mint.TerminalControlInput{
		Issuer: s.issuer, EnvironmentID: environmentID, UserID: userID, JTI: newID("jti"), Nonce: newID("nonce"),
		IssuedAt: s.now().UTC(), ExpiresAt: s.now().UTC().Add(mint.MaxProofTTL), Operation: operation,
		ThreadID: threadID, TerminalIDs: []string{terminalID},
	})
	if err == nil {
		err = s.postTerminalControl(ctx, route.String, proof, operation)
	}
	if err != nil {
		return s.retryTerminalSessionOperation(ctx, operationID, attempts, err)
	}
	return s.db.Queries().MarkConnectedMachineTerminalSessionOperationApplied(ctx, operationID)
}

func (s *Service) postTerminalControl(ctx context.Context, route, proof, expectedOperation string) error {
	body, err := json.Marshal(map[string]string{"proof": proof})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(route, "/")+"/api/paperboat/terminal-sessions/control", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.controlHTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("Papercode terminal control returned HTTP %d", resp.StatusCode)
	}
	var payload struct {
		Operation string `json:"operation"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return err
	}
	if payload.Operation != expectedOperation {
		return fmt.Errorf("Papercode terminal control returned operation %q for %q", payload.Operation, expectedOperation)
	}
	return nil
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
	n, err := s.db.Queries().RevokeConnectedMachine(ctx, dbsqlc.RevokeConnectedMachineParams{ID: machineID, UserID: userID, State: "disconnected", SeatState: "released"})
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	auditErr := s.audit.Write(ctx, audit.Event{ActorUserID: userID, ActorType: audit.ActorUser, EventType: "connected_machine.disconnected", ResourceType: "connected_machine", ResourceID: machineID, IdempotencyKey: "connected_machine.disconnected:" + machineID, Metadata: map[string]any{}})
	return errors.Join(auditErr, s.RevokeMachineSessions(ctx, machineID, "connected_machine_disconnected"))
}

func (s *Service) Delete(ctx context.Context, userID, machineID string) error {
	n, err := s.db.Queries().DeleteConnectedMachine(ctx, dbsqlc.DeleteConnectedMachineParams{ID: machineID, UserID: userID})
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	auditErr := s.audit.Write(ctx, audit.Event{ActorUserID: userID, ActorType: audit.ActorUser, EventType: "connected_machine.deleted", ResourceType: "connected_machine", ResourceID: machineID, IdempotencyKey: "connected_machine.deleted:" + machineID, Metadata: map[string]any{}})
	return errors.Join(auditErr, s.RevokeMachineSessions(ctx, machineID, "connected_machine_deleted"))
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

// RevokeEntitlementLostUserSessions is safe to call after every billing
// webhook. It only revokes sessions when the persisted entitlement is no
// longer active for the current period, keeping the billing side effect
// independent from provider event ordering.
func (s *Service) RevokeEntitlementLostUserSessions(ctx context.Context, userID string) error {
	if strings.TrimSpace(userID) == "" {
		return errors.New("connected-machine entitlement user is required")
	}
	active, err := s.db.Queries().ConnectedMachineEntitlementIsActive(ctx, userID)
	if err != nil {
		return err
	}
	if active {
		return nil
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
	if s.credentials == nil {
		return errors.New("connected-machine credential issuer is unavailable")
	}
	sessionIDs := compactSessionIDs(session.TerminalSessionID, session.FileSessionID)
	if len(sessionIDs) == 0 {
		return nil
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
	if s.policy.PairingLifetime <= 0 || strings.TrimSpace(in.Verifier) == "" || strings.TrimSpace(in.DisplayName) == "" || strings.TrimSpace(in.Architecture) == "" || !filepath.IsAbs(in.WorkspaceRoot) || !slices.Contains(s.policy.AllowedPlatforms, strings.ToLower(strings.TrimSpace(in.Platform))) {
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
