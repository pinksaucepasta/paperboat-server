package tunnelv1

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
	"github.com/pinksaucepasta/paperboat-server/internal/previewtunnelapi"
)

var (
	ErrConflict                   = errors.New("tunnel persistence conflict")
	ErrNameConflict               = errors.New("tunnel name is already in use")
	ErrGenerationConflict         = errors.New("tunnel generation conflict")
	ErrIdempotencyConflict        = errors.New("idempotency key was reused with different input")
	ErrInvalidInput               = errors.New("invalid tunnel persistence input")
	ErrNotFound                   = errors.New("tunnel not found")
	ErrHostNotFound               = errors.New("host is not owned by this account")
	ErrTerminalState              = errors.New("tunnel is already deleted")
	ErrOperationInProgress        = errors.New("tunnel operation is still in progress")
	ErrRouteConflict              = errors.New("route conflicts with an existing route")
	ErrDomainConflict             = errors.New("domain binding conflicts with an existing binding")
	ErrConnectorConflict          = errors.New("connector conflicts with an existing connector")
	ErrConnectorNotFound          = errors.New("connector not found")
	ErrRouteNotFound              = errors.New("route not found")
	ErrDomainNotFound             = errors.New("domain binding not found")
	ErrEnrollmentExpired          = errors.New("connector enrollment expired")
	ErrEnrollmentReplay           = errors.New("connector enrollment was already consumed")
	ErrEnrollmentAlreadyIssued    = errors.New("connector enrollment was already issued")
	ErrDNSInstructionsUnavailable = errors.New("dns instructions are unavailable for this domain")
	ErrConfigGenerationChain      = errors.New("tunnel configuration generation chain is incomplete")
)

// TunnelRepository is the narrow persistence boundary used by the lifecycle
// service. Keeping it small makes policy tests independent of PostgreSQL while
// keeping all mutation transactions in the SQL implementation.
type TunnelRepository interface {
	VerifyHost(context.Context, string, string) error
	Create(context.Context, CreateRecord) (MutationRecord, error)
	Get(context.Context, string, string) (dbsqlc.Tunnel, error)
	List(context.Context, string, *ListPosition, int) ([]dbsqlc.Tunnel, error)
	Patch(context.Context, PatchRecord) (MutationRecord, error)
	Transition(context.Context, StateRecord) (MutationRecord, error)
	ReconcileExpired(context.Context, ExpiryRecord) ([]MutationRecord, error)
}

type CreateRecord struct {
	OperationID      string
	TunnelID         string
	StableEndpointID string
	StableEndpoint   string
	AccountID        string
	Name             string
	AccessMode       string
	Origin           OriginRequest
	ExpiresAt        sql.NullTime
	IdempotencyKey   string
	RequestHash      [sha256.Size]byte
	ActorID          string
	AuditActorID     string
	ActorType        string
	HostID           string
	RequestID        string
	CorrelationID    string
	SourceDeviceID   string
	AuditEventID     string
}

type PatchRecord struct {
	OperationID        string
	AuditEventID       string
	TunnelID           string
	AccountID          string
	Name               *string
	AccessMode         *string
	ExpiresAt          *time.Time
	ExpirySet          bool
	ExpectedGeneration int64
	IdempotencyKey     string
	RequestHash        [sha256.Size]byte
	ActorID            string
	AuditActorID       string
	ActorType          string
	RequestID          string
	CorrelationID      string
	SourceDeviceID     string
	// Now is supplied by the service clock so expiry validation and audit
	// transitions remain deterministic in tests and replay paths.
	Now time.Time
}

type StateRecord struct {
	OperationID        string
	AuditEventID       string
	TunnelID           string
	AccountID          string
	DesiredState       string
	ExpectedGeneration int64
	IdempotencyKey     string
	RequestHash        [sha256.Size]byte
	ActorID            string
	AuditActorID       string
	ActorType          string
	RequestID          string
	CorrelationID      string
	SourceDeviceID     string
}

type MutationRecord struct {
	Tunnel    dbsqlc.Tunnel
	Operation dbsqlc.Operation
	Replayed  bool
	Changed   bool
}

type ExpiryRecord struct {
	Now           time.Time
	Limit         int
	ActorID       string
	ActorType     string
	RequestID     string
	CorrelationID string
	NewID         func(string) (string, error)
}

type ListPosition struct {
	CreatedAt time.Time
	ID        string
}

type SQLRepository struct {
	db  *db.DB
	now func() time.Time
}

func NewRepository(database *db.DB) (*SQLRepository, error) {
	if database == nil {
		return nil, fmt.Errorf("%w: database is required", ErrInvalidInput)
	}
	return &SQLRepository{db: database, now: func() time.Time { return time.Now().UTC() }}, nil
}

func (r *SQLRepository) VerifyHost(ctx context.Context, accountID, hostID string) error {
	if strings.TrimSpace(accountID) == "" || strings.TrimSpace(hostID) == "" {
		return ErrHostNotFound
	}
	return verifyHostWithQueries(ctx, r.db.Queries(), accountID, hostID)
}

func verifyHostWithQueries(ctx context.Context, queries *dbsqlc.Queries, accountID, hostID string) error {
	_, err := queries.GetOwnedActivePreviewTunnelHostV1(ctx, dbsqlc.GetOwnedActivePreviewTunnelHostV1Params{
		HostID: hostID, AccountID: accountID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrHostNotFound
	}
	return translate(err)
}

func (r *SQLRepository) Get(ctx context.Context, accountID, tunnelID string) (dbsqlc.Tunnel, error) {
	if strings.TrimSpace(accountID) == "" || strings.TrimSpace(tunnelID) == "" {
		return dbsqlc.Tunnel{}, ErrInvalidInput
	}
	tunnel, err := r.db.Queries().GetPreviewTunnel(ctx, dbsqlc.GetPreviewTunnelParams{ID: tunnelID, AccountID: accountID})
	return tunnel, translate(err)
}

func (r *SQLRepository) List(ctx context.Context, accountID string, after *ListPosition, limit int) ([]dbsqlc.Tunnel, error) {
	if strings.TrimSpace(accountID) == "" || limit < 1 || limit > previewtunnelapi.MaximumPageLimit+1 {
		return nil, ErrInvalidInput
	}
	var afterCreatedAt sql.NullTime
	var afterID sql.NullString
	if after != nil {
		if after.ID == "" || after.CreatedAt.IsZero() {
			return nil, ErrInvalidInput
		}
		afterCreatedAt = sql.NullTime{Time: after.CreatedAt.UTC(), Valid: true}
		afterID = nullableString(after.ID)
	}
	items, err := r.db.Queries().ListPreviewTunnelsV1(ctx, dbsqlc.ListPreviewTunnelsV1Params{
		AccountID: accountID, AfterCreatedAt: afterCreatedAt, AfterID: afterID, RowLimit: int32(limit),
	})
	return items, translate(err)
}

func (r *SQLRepository) Create(ctx context.Context, input CreateRecord) (MutationRecord, error) {
	if err := validateCreateRecord(input); err != nil {
		return MutationRecord{}, err
	}
	var result MutationRecord
	err := r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		queries := tx.Queries()
		// Recheck and lock the structural host identity inside the create
		// transaction. The preflight service check alone would allow a
		// concurrent revoke/delete to race the durable tunnel insert.
		if err := verifyHostWithQueries(ctx, queries, input.AccountID, input.HostID); err != nil {
			return err
		}
		operation, replayed, err := beginOperation(ctx, queries, operationInput{
			ID: input.OperationID, AccountID: input.AccountID, IdempotencyKey: input.IdempotencyKey,
			RequestHash: input.RequestHash, OperationType: "tunnel.create", CorrelationID: input.CorrelationID,
		})
		if err != nil {
			return err
		}
		if replayed {
			if !operation.ResourceID.Valid {
				return ErrOperationInProgress
			}
			tunnel, getErr := queries.GetPreviewTunnel(ctx, dbsqlc.GetPreviewTunnelParams{ID: operation.ResourceID.String, AccountID: input.AccountID})
			if getErr != nil {
				return translate(getErr)
			}
			result = MutationRecord{Tunnel: tunnel, Operation: operation, Replayed: true}
			return nil
		}

		now := r.now().UTC()
		tunnel, err := queries.CreatePreviewTunnel(ctx, dbsqlc.CreatePreviewTunnelParams{
			ID: input.TunnelID, AccountID: input.AccountID, Name: input.Name,
			DesiredState: DesiredActive, AccessMode: input.AccessMode,
			StableEndpointID: input.StableEndpointID, StableEndpoint: input.StableEndpoint,
			CreatedByHostID: input.HostID, CreatedByActorID: input.ActorID,
			ExpiresAt: input.ExpiresAt, SummaryCode: "pending", Now: now,
		})
		if err != nil {
			return translate(err)
		}
		route, err := createInitialRoute(ctx, queries, input, tunnel, now)
		if err != nil {
			return err
		}
		if err := createInitialConfigGeneration(ctx, queries, input, tunnel, route, now); err != nil {
			return err
		}
		if err := insertAudit(ctx, queries, input.AuditEventID, input.AccountID, auditActorID(input.ActorID, input.AuditActorID), input.ActorType,
			"tunnel.created", "create", "changed", tunnel.ID, input.IdempotencyKey, input.RequestID,
			input.CorrelationID, input.SourceDeviceID, now, map[string]any{
				"access_mode": input.AccessMode, "generation": tunnel.Generation,
			}); err != nil {
			return err
		}
		operation, err = advanceOperation(ctx, queries, operation.ID, tunnel.ID, "connecting", 40, now)
		if err != nil {
			return err
		}
		result = MutationRecord{Tunnel: tunnel, Operation: operation, Changed: true}
		return nil
	})
	return result, err
}

func (r *SQLRepository) Patch(ctx context.Context, input PatchRecord) (MutationRecord, error) {
	if err := validatePatchRecord(input); err != nil {
		return MutationRecord{}, err
	}
	var result MutationRecord
	err := r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		queries := tx.Queries()
		operation, replayed, err := beginOperation(ctx, queries, operationInput{
			ID: input.OperationID, AccountID: input.AccountID, IdempotencyKey: input.IdempotencyKey,
			RequestHash: input.RequestHash, OperationType: "tunnel.patch", CorrelationID: input.CorrelationID,
		})
		if err != nil {
			return err
		}
		if replayed {
			if !operation.ResourceID.Valid || operation.ResourceID.String != input.TunnelID {
				return ErrIdempotencyConflict
			}
			tunnel, getErr := queries.GetPreviewTunnel(ctx, dbsqlc.GetPreviewTunnelParams{ID: input.TunnelID, AccountID: input.AccountID})
			if getErr != nil {
				return translate(getErr)
			}
			result = MutationRecord{Tunnel: tunnel, Operation: operation, Replayed: true, Changed: operation.Outcome == "changed"}
			return nil
		}

		current, err := queries.GetPreviewTunnel(ctx, dbsqlc.GetPreviewTunnelParams{ID: input.TunnelID, AccountID: input.AccountID})
		if err != nil {
			return translate(err)
		}
		if current.DesiredState == DesiredDeleted {
			return ErrTerminalState
		}
		if current.Generation != input.ExpectedGeneration {
			return ErrGenerationConflict
		}
		// A public endpoint cannot expose a TCP route. Check the durable route
		// rows in this SERIALIZABLE transaction immediately before the tunnel
		// CAS so a concurrent route mutation cannot turn this into a public
		// TCP tunnel between validation and commit.
		effectiveAccessMode := current.AccessMode
		if input.AccessMode != nil {
			effectiveAccessMode = *input.AccessMode
		}
		if effectiveAccessMode == AccessPublic {
			hasPrivateTCPRoute, routeErr := queries.HasActivePrivateTCPRouteV1(ctx, current.ID)
			if routeErr != nil {
				return translate(routeErr)
			}
			if hasPrivateTCPRoute {
				return fmt.Errorf("%w: public access is not allowed for a TCP route", ErrInvalidInput)
			}
		}
		changed := patchChanges(current, input)
		now := r.now().UTC()
		if changed {
			updated, updateErr := updateTunnelFields(ctx, tx, input, now)
			if updateErr != nil {
				return updateErr
			}
			current = updated
			if err := createResourceConfigGeneration(ctx, queries, current, input.ActorID, now); err != nil {
				return err
			}
		}
		outcome := "unchanged"
		if changed {
			outcome = "changed"
		}
		if changed {
			operation, err = advanceOperation(ctx, queries, operation.ID, current.ID, "connecting", 60, now)
		} else {
			operation, err = completeOperation(ctx, queries, operation.ID, current.ID, "ready", outcome, now)
		}
		if err != nil {
			return err
		}
		if err := insertAudit(ctx, queries, input.AuditEventID, input.AccountID, auditActorID(input.ActorID, input.AuditActorID), input.ActorType,
			"tunnel.updated", "update", outcome, current.ID, input.IdempotencyKey, input.RequestID,
			input.CorrelationID, input.SourceDeviceID, now, map[string]any{
				"generation": current.Generation, "desired_state": current.DesiredState,
			}); err != nil {
			return err
		}
		result = MutationRecord{Tunnel: current, Operation: operation, Changed: changed}
		return nil
	})
	return result, err
}

func (r *SQLRepository) Transition(ctx context.Context, input StateRecord) (MutationRecord, error) {
	if err := validateStateRecord(input); err != nil {
		return MutationRecord{}, err
	}
	var result MutationRecord
	err := r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		queries := tx.Queries()
		operation, replayed, err := beginOperation(ctx, queries, operationInput{
			ID: input.OperationID, AccountID: input.AccountID, IdempotencyKey: input.IdempotencyKey,
			RequestHash: input.RequestHash, OperationType: "tunnel." + stateOperationName(input.DesiredState), CorrelationID: input.CorrelationID,
		})
		if err != nil {
			return err
		}
		if replayed {
			if !operation.ResourceID.Valid || operation.ResourceID.String != input.TunnelID {
				return ErrIdempotencyConflict
			}
			tunnel, getErr := queries.GetPreviewTunnel(ctx, dbsqlc.GetPreviewTunnelParams{ID: input.TunnelID, AccountID: input.AccountID})
			if getErr != nil {
				return translate(getErr)
			}
			result = MutationRecord{Tunnel: tunnel, Operation: operation, Replayed: true, Changed: operation.Outcome == "changed"}
			return nil
		}

		current, err := queries.GetPreviewTunnel(ctx, dbsqlc.GetPreviewTunnelParams{ID: input.TunnelID, AccountID: input.AccountID})
		if err != nil {
			return translate(err)
		}
		if current.DesiredState != DesiredDeleted && current.Generation != input.ExpectedGeneration {
			return ErrGenerationConflict
		}
		if input.DesiredState != DesiredDeleted && current.DesiredState == DesiredDeleted {
			return ErrTerminalState
		}
		previousState := current.DesiredState
		changed := current.DesiredState != input.DesiredState
		now := r.now().UTC()
		if changed {
			updated, updateErr := queries.UpdatePreviewTunnelDesiredState(ctx, dbsqlc.UpdatePreviewTunnelDesiredStateParams{
				DesiredState: input.DesiredState, Now: now, ID: input.TunnelID,
				AccountID: input.AccountID, ExpectedGeneration: input.ExpectedGeneration,
			})
			if errors.Is(updateErr, pgx.ErrNoRows) {
				return ErrGenerationConflict
			}
			if updateErr != nil {
				return translate(updateErr)
			}
			current = updated
			if err := createResourceConfigGeneration(ctx, queries, current, input.ActorID, now); err != nil {
				return err
			}
		}
		outcome := "unchanged"
		if changed {
			outcome = "changed"
		}
		if changed {
			phase := "connecting"
			if input.DesiredState == DesiredPaused || input.DesiredState == DesiredDeleted {
				phase = "draining"
			}
			operation, err = advanceOperation(ctx, queries, operation.ID, current.ID, phase, 60, now)
		} else {
			operation, err = completeOperation(ctx, queries, operation.ID, current.ID, "ready", outcome, now)
		}
		if err != nil {
			return err
		}
		eventType := "tunnel." + stateOperationName(input.DesiredState)
		if err := insertAudit(ctx, queries, input.AuditEventID, input.AccountID, auditActorID(input.ActorID, input.AuditActorID), input.ActorType,
			eventType, stateOperationName(input.DesiredState), outcome, current.ID, input.IdempotencyKey, input.RequestID,
			input.CorrelationID, input.SourceDeviceID, now, map[string]any{
				"previous_state": previousState,
				"desired_state":  current.DesiredState,
				"generation":     current.Generation,
			}); err != nil {
			return err
		}
		result = MutationRecord{Tunnel: current, Operation: operation, Changed: changed}
		return nil
	})
	return result, err
}

// ReconcileExpired marks the observed tunnel summary as expired without
// changing durable desired_state, generation, endpoint identity, routes, or
// domains. Row locks and SKIP LOCKED make concurrent workers safe; the
// deterministic operation key makes a retried worker idempotent.
func (r *SQLRepository) ReconcileExpired(ctx context.Context, input ExpiryRecord) ([]MutationRecord, error) {
	if input.Now.IsZero() {
		input.Now = r.now().UTC()
	}
	if input.Limit < 1 || input.Limit > 200 || strings.TrimSpace(input.ActorID) == "" || !validActorType(input.ActorType) || strings.TrimSpace(input.CorrelationID) == "" {
		return nil, ErrInvalidInput
	}
	if input.NewID == nil {
		input.NewID = randomID
	}
	var result []MutationRecord
	err := r.db.InReadCommittedTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		rows, err := tx.Queries().ListExpiredPreviewTunnelsV1(ctx, dbsqlc.ListExpiredPreviewTunnelsV1Params{
			Now: sql.NullTime{Time: input.Now.UTC(), Valid: true}, RowLimit: int32(input.Limit),
		})
		if err != nil {
			return translate(err)
		}
		for _, tunnel := range rows {
			if !tunnel.ExpiresAt.Valid {
				continue
			}
			operationKey := "tunnel.expire:" + tunnel.ID + ":" + tunnel.ExpiresAt.Time.UTC().Format(time.RFC3339Nano)
			hash := sha256.Sum256([]byte(operationKey))
			operationID, idErr := input.NewID("op")
			if idErr != nil {
				return idErr
			}
			auditID, idErr := input.NewID("aud")
			if idErr != nil {
				return idErr
			}
			operation, replayed, opErr := beginOperation(ctx, tx.Queries(), operationInput{
				ID: operationID, AccountID: tunnel.AccountID, IdempotencyKey: operationKey,
				RequestHash: hash, OperationType: "tunnel.expire", CorrelationID: input.CorrelationID,
			})
			if opErr != nil {
				return opErr
			}
			if replayed {
				result = append(result, MutationRecord{Tunnel: tunnel, Operation: operation, Replayed: true, Changed: operation.Outcome == "changed"})
				continue
			}
			now := input.Now.UTC()
			updated, updateErr := tx.Queries().MarkExpiredPreviewTunnelV1(ctx, dbsqlc.MarkExpiredPreviewTunnelV1Params{
				Now: now, ID: tunnel.ID, AccountID: tunnel.AccountID,
			})
			if errors.Is(updateErr, pgx.ErrNoRows) {
				// Another worker can only reach this branch after the lock is
				// released, but treating it as an unchanged result keeps expiry
				// repair idempotent if a future query shape changes.
				updated = tunnel
			} else if updateErr != nil {
				return translate(updateErr)
			}
			operation, err = completeOperation(ctx, tx.Queries(), operation.ID, updated.ID, "ready", expiryOutcome(tunnel, updated), now)
			if err != nil {
				return err
			}
			if err := insertAudit(ctx, tx.Queries(), auditID, updated.AccountID, input.ActorID, input.ActorType,
				"tunnel.expired", "expire", expiryOutcome(tunnel, updated), updated.ID, operationKey, input.RequestID,
				input.CorrelationID, "", now, map[string]any{
					"expires_at":    tunnel.ExpiresAt.Time.UTC().Format(time.RFC3339Nano),
					"desired_state": updated.DesiredState,
					"generation":    updated.Generation,
				}); err != nil {
				return err
			}
			result = append(result, MutationRecord{Tunnel: updated, Operation: operation, Changed: expiryOutcome(tunnel, updated) == "changed"})
		}
		return nil
	})
	return result, translate(err)
}

type operationInput struct {
	ID             string
	AccountID      string
	IdempotencyKey string
	RequestHash    [sha256.Size]byte
	OperationType  string
	CorrelationID  string
}

func beginOperation(ctx context.Context, queries *dbsqlc.Queries, input operationInput) (dbsqlc.Operation, bool, error) {
	operation, err := queries.CreatePreviewTunnelOperation(ctx, dbsqlc.CreatePreviewTunnelOperationParams{
		ID: input.ID, AccountID: input.AccountID, IdempotencyKey: input.IdempotencyKey,
		RequestHash: input.RequestHash[:], OperationType: input.OperationType, ResourceKind: "tunnel",
		Phase: "persisting", State: "running", Progress: 20, Outcome: "unchanged", CorrelationID: input.CorrelationID,
	})
	if err == nil {
		return operation, false, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return dbsqlc.Operation{}, false, translate(err)
	}
	existing, getErr := queries.GetPreviewTunnelOperationByIdempotency(ctx, dbsqlc.GetPreviewTunnelOperationByIdempotencyParams{
		AccountID: input.AccountID, IdempotencyKey: input.IdempotencyKey,
	})
	if getErr != nil {
		return dbsqlc.Operation{}, false, translate(getErr)
	}
	if existing.OperationType != input.OperationType || existing.ResourceKind != "tunnel" || !bytes.Equal(existing.RequestHash, input.RequestHash[:]) {
		return dbsqlc.Operation{}, false, ErrIdempotencyConflict
	}
	return existing, true, nil
}

func completeOperation(ctx context.Context, queries *dbsqlc.Queries, operationID, resourceID, phase, outcome string, now time.Time) (dbsqlc.Operation, error) {
	operation, err := queries.CompletePreviewTunnelOperation(ctx, dbsqlc.CompletePreviewTunnelOperationParams{
		ResourceID: sql.NullString{String: resourceID, Valid: true}, Phase: phase, State: "succeeded",
		Progress: 100, Outcome: outcome, ResultReference: sql.NullString{String: resourceID, Valid: true},
		UpdatedAt: now, CompletedAt: sql.NullTime{Time: now, Valid: true}, ID: operationID,
	})
	return operation, translate(err)
}

// advanceOperation deliberately reuses the generated completion query while
// keeping the operation running. This keeps the operation update in the same
// sqlc source of truth as terminal completion and leaves completed_at NULL
// until a reconciler observes readiness or drain completion.
func advanceOperation(ctx context.Context, queries *dbsqlc.Queries, operationID, resourceID, phase string, progress int16, now time.Time) (dbsqlc.Operation, error) {
	operation, err := queries.CompletePreviewTunnelOperation(ctx, dbsqlc.CompletePreviewTunnelOperationParams{
		ResourceID: sql.NullString{String: resourceID, Valid: true}, Phase: phase, State: "running",
		Progress: progress, Outcome: "changed", ResultReference: sql.NullString{},
		UpdatedAt: now.UTC(), CompletedAt: sql.NullTime{}, ID: operationID,
	})
	return operation, translate(err)
}

func insertAudit(ctx context.Context, queries *dbsqlc.Queries, id, accountID, actorID, actorType, eventType, changeType, outcome, resourceID, idempotencyKey, requestID, correlationID, sourceDeviceID string, createdAt time.Time, metadata map[string]any) error {
	safe, err := previewtunnelapi.SafeMetadata(metadata)
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(safe)
	if err != nil {
		return fmt.Errorf("encode tunnel audit metadata: %w", err)
	}
	_, err = queries.InsertPreviewTunnelAuditEvent(ctx, dbsqlc.InsertPreviewTunnelAuditEventParams{
		ID: id, AccountID: nullableString(accountID), ActorID: nullableString(actorID),
		ActorUserID: actorUserID(actorType, actorID), ActorType: actorType, EventType: eventType,
		ChangeType: changeType, Outcome: outcome, ResourceType: "tunnel", ResourceID: resourceID,
		IdempotencyKey: nullableString(idempotencyKey), RequestID: nullableString(requestID),
		CorrelationID: nullableString(correlationID), SourceDeviceID: nullableString(sourceDeviceID),
		Metadata: encoded, CreatedAt: createdAt.UTC(),
	})
	return translate(err)
}

func createInitialRoute(ctx context.Context, queries *dbsqlc.Queries, input CreateRecord, tunnel dbsqlc.Tunnel, now time.Time) (dbsqlc.TunnelRoute, error) {
	parsed, err := url.Parse(tunnel.StableEndpoint)
	if err != nil || parsed.Hostname() == "" {
		return dbsqlc.TunnelRoute{}, fmt.Errorf("%w: stable endpoint hostname is invalid", ErrInvalidInput)
	}
	preserveHost := true
	if input.Origin.PreserveHost != nil {
		preserveHost = *input.Origin.PreserveHost
	}
	var hostOverride sql.NullString
	if input.Origin.HostOverride != nil {
		hostOverride = nullableString(*input.Origin.HostOverride)
	}
	protocol := "http"
	matchType := "managed"
	matchHostname := nullableString(strings.ToLower(parsed.Hostname()))
	tlsVerification := "not_applicable"
	if input.Origin.Scheme == "https" {
		tlsVerification = "system"
	}
	if input.Origin.Scheme == "tcp" {
		protocol = "private_tcp"
		// Private TCP is an unhosted catch-all route. A managed hostname would
		// imply a public HTTP binding and violate the route wire contract.
		matchType = "catch_all"
		matchHostname = sql.NullString{}
	}
	return queries.CreatePreviewTunnelRoute(ctx, dbsqlc.CreatePreviewTunnelRouteParams{
		ID: newRouteID(tunnel.ID), TunnelID: tunnel.ID, Name: "default", Protocol: protocol,
		MatchType: matchType, MatchHostname: matchHostname,
		Priority: 100, OriginScheme: input.Origin.Scheme, OriginAddress: input.Origin.Address,
		PreserveHost: preserveHost, HostOverride: hostOverride, TlsVerification: tlsVerification,
		ConnectTimeoutMs: 10000, IdleTimeoutMs: 90000, MaxConcurrentStreams: 128,
		DesiredState: DesiredActive, CreatedByActorID: input.ActorID, UpdatedByActorID: input.ActorID, Now: now,
	})
}

const configGenerationRetention = 90 * 24 * time.Hour

// createInitialConfigGeneration commits the first complete desired-state
// snapshot with the tunnel and route. It remains pending until a connector
// validates/applies it, so API persistence never masquerades as readiness.
func createInitialConfigGeneration(ctx context.Context, queries *dbsqlc.Queries, input CreateRecord, tunnel dbsqlc.Tunnel, route dbsqlc.TunnelRoute, now time.Time) error {
	snapshot, err := initialConfigSnapshot(tunnel, route)
	if err != nil {
		return err
	}
	hash := sha256.Sum256(snapshot)
	_, err = queries.CreatePreviewTunnelConfigGeneration(ctx, dbsqlc.CreatePreviewTunnelConfigGenerationParams{
		TunnelID: tunnel.ID, Generation: tunnel.Generation, ContentHash: hash[:], Snapshot: snapshot,
		ActivationState: "pending", CreatedByActorID: input.ActorID, Now: now,
		RetainedUntil: now.Add(configGenerationRetention),
	})
	return translate(err)
}

type initialTunnelConfigSnapshot struct {
	Schema         string                       `json:"schema"`
	Kind           string                       `json:"kind"`
	TunnelID       string                       `json:"tunnel_id"`
	Generation     int64                        `json:"generation"`
	Name           string                       `json:"name"`
	DesiredState   string                       `json:"desired_state"`
	AccessMode     string                       `json:"access_mode"`
	StableEndpoint string                       `json:"stable_endpoint"`
	ExpiresAt      *time.Time                   `json:"expires_at"`
	Routes         []initialTunnelRouteSnapshot `json:"routes"`
}

type initialTunnelRouteSnapshot struct {
	ID                      string  `json:"id"`
	Name                    string  `json:"name"`
	Protocol                string  `json:"protocol"`
	MatchType               string  `json:"match_type"`
	MatchHostname           string  `json:"match_hostname,omitempty"`
	WildcardSuffix          string  `json:"wildcard_suffix,omitempty"`
	PathPrefix              *string `json:"path_prefix"`
	OriginScheme            string  `json:"origin_scheme"`
	OriginAddress           string  `json:"origin_address"`
	PreserveHost            bool    `json:"preserve_host"`
	HostOverride            *string `json:"host_override"`
	TLSVerification         string  `json:"tls_verification"`
	TLSServerName           *string `json:"tls_server_name"`
	CAReference             *string `json:"ca_reference"`
	MTLSCredentialReference *string `json:"mtls_credential_reference"`
	ConnectTimeoutMs        int32   `json:"connect_timeout_ms"`
	IdleTimeoutMs           int32   `json:"idle_timeout_ms"`
	MaxStreams              int32   `json:"max_concurrent_streams"`
	DesiredState            string  `json:"desired_state"`
}

func initialConfigSnapshot(tunnel dbsqlc.Tunnel, route dbsqlc.TunnelRoute) ([]byte, error) {
	var expiresAt *time.Time
	if tunnel.ExpiresAt.Valid {
		value := tunnel.ExpiresAt.Time.UTC()
		expiresAt = &value
	}
	snapshot := initialTunnelConfigSnapshot{
		Schema: Schema, Kind: "tunnel_config_snapshot", TunnelID: tunnel.ID, Generation: tunnel.Generation,
		Name: tunnel.Name, DesiredState: tunnel.DesiredState, AccessMode: tunnel.AccessMode, StableEndpoint: tunnel.StableEndpoint,
		ExpiresAt: expiresAt,
		Routes:    []initialTunnelRouteSnapshot{snapshotRoute(route)},
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		return nil, fmt.Errorf("encode initial tunnel configuration: %w", err)
	}
	return canonicalConfigSnapshot(encoded)
}

// canonicalConfigSnapshot mirrors connectorprotocol's compact JSON hashing
// boundary. JSONB is a semantic storage type and may reorder object keys or
// add whitespace, so generation hashes must always describe these canonical
// bytes before they are persisted as bytea.
func canonicalConfigSnapshot(payload []byte) ([]byte, error) {
	if len(payload) == 0 {
		return nil, fmt.Errorf("empty tunnel configuration snapshot")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, fmt.Errorf("decode tunnel configuration snapshot: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return nil, fmt.Errorf("decode tunnel configuration snapshot: %w", err)
	}
	if _, ok := value.(map[string]any); !ok {
		return nil, fmt.Errorf("tunnel configuration snapshot must be a JSON object")
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("encode canonical tunnel configuration snapshot: %w", err)
	}
	return encoded, nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("trailing JSON value")
		}
		return err
	}
	return nil
}

func snapshotRoute(route dbsqlc.TunnelRoute) initialTunnelRouteSnapshot {
	var pathPrefix *string
	if route.PathPrefix.Valid {
		value := route.PathPrefix.String
		pathPrefix = &value
	}
	var hostOverride *string
	if route.HostOverride.Valid {
		value := route.HostOverride.String
		hostOverride = &value
	}
	var serverName, caReference, mtlsReference *string
	if route.TlsServerName.Valid {
		value := route.TlsServerName.String
		serverName = &value
	}
	if route.CaReference.Valid {
		value := route.CaReference.String
		caReference = &value
	}
	if route.MtlsCredentialReference.Valid {
		value := route.MtlsCredentialReference.String
		mtlsReference = &value
	}
	return initialTunnelRouteSnapshot{
		ID: route.ID, Name: route.Name, Protocol: wireProtocol(route.Protocol), MatchType: wireMatchType(route.MatchType),
		MatchHostname: nullableStringValue(route.MatchHostname), WildcardSuffix: nullableStringValue(route.WildcardSuffix), PathPrefix: pathPrefix,
		OriginScheme: route.OriginScheme, OriginAddress: route.OriginAddress, PreserveHost: route.PreserveHost, HostOverride: hostOverride,
		TLSVerification: route.TlsVerification, TLSServerName: serverName, CAReference: caReference, MTLSCredentialReference: mtlsReference,
		ConnectTimeoutMs: route.ConnectTimeoutMs, IdleTimeoutMs: route.IdleTimeoutMs, MaxStreams: route.MaxConcurrentStreams,
		DesiredState: route.DesiredState,
	}
}

func updateTunnelFields(ctx context.Context, tx *db.Tx, input PatchRecord, now time.Time) (dbsqlc.Tunnel, error) {
	var name sql.NullString
	if input.Name != nil {
		name = nullableString(*input.Name)
	}
	var accessMode sql.NullString
	if input.AccessMode != nil {
		accessMode = nullableString(*input.AccessMode)
	}
	var expiresAt sql.NullTime
	if input.ExpiresAt != nil {
		expiresAt = sql.NullTime{Time: input.ExpiresAt.UTC(), Valid: true}
	}
	tunnel, err := tx.Queries().UpdatePreviewTunnelFieldsV1(ctx, dbsqlc.UpdatePreviewTunnelFieldsV1Params{
		NameSet: input.Name != nil, Name: name, AccessModeSet: input.AccessMode != nil, AccessMode: accessMode,
		ExpiresAtSet: input.ExpirySet, ExpiresAt: expiresAt, Now: now, ID: input.TunnelID,
		AccountID: input.AccountID, ExpectedGeneration: input.ExpectedGeneration,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return dbsqlc.Tunnel{}, ErrGenerationConflict
	}
	return tunnel, translate(err)
}

func patchChanges(current dbsqlc.Tunnel, input PatchRecord) bool {
	if input.Name != nil && current.Name != *input.Name {
		return true
	}
	if input.AccessMode != nil && current.AccessMode != *input.AccessMode {
		return true
	}
	if input.ExpirySet {
		if input.ExpiresAt == nil {
			return current.ExpiresAt.Valid
		}
		return !current.ExpiresAt.Valid || !current.ExpiresAt.Time.Equal(input.ExpiresAt.UTC())
	}
	return false
}

func expiryOutcome(previous, updated dbsqlc.Tunnel) string {
	if previous.SummaryCode == updated.SummaryCode || updated.SummaryCode != "expired" {
		return "unchanged"
	}
	return "changed"
}

func stateOperationName(state string) string {
	switch state {
	case DesiredPaused:
		return "paused"
	case DesiredActive:
		return "resumed"
	case DesiredDeleted:
		return "deleted"
	default:
		return "state_changed"
	}
}

func validateCreateRecord(input CreateRecord) error {
	for name, value := range map[string]string{
		"operation_id": input.OperationID, "tunnel_id": input.TunnelID,
		"stable_endpoint_id": input.StableEndpointID, "stable_endpoint": input.StableEndpoint,
		"account_id": input.AccountID, "name": input.Name, "access_mode": input.AccessMode,
		"idempotency_key": input.IdempotencyKey, "actor_id": input.ActorID,
		"host_id": input.HostID, "actor_type": input.ActorType, "correlation_id": input.CorrelationID,
		"audit_event_id": input.AuditEventID,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%w: %s is required", ErrInvalidInput, name)
		}
	}
	if input.RequestHash == ([sha256.Size]byte{}) {
		return fmt.Errorf("%w: request hash is required", ErrInvalidInput)
	}
	if _, err := validateTunnelName(input.Name); err != nil {
		return err
	}
	if err := validateStableEndpointForID(input.StableEndpoint, input.StableEndpointID); err != nil {
		return err
	}
	if !validActorType(input.ActorType) {
		return fmt.Errorf("%w: actor type is invalid", ErrInvalidInput)
	}
	if input.AccessMode != AccessPublic && input.AccessMode != AccessPrivate {
		return fmt.Errorf("%w: access mode is invalid", ErrInvalidInput)
	}
	if input.Origin.Scheme == "tcp" && input.AccessMode != AccessPrivate {
		return fmt.Errorf("%w: tcp origins require private access", ErrInvalidInput)
	}
	return validateOrigin(input.Origin)
}

func validatePatchRecord(input PatchRecord) error {
	for name, value := range map[string]string{
		"operation_id": input.OperationID, "audit_event_id": input.AuditEventID,
		"tunnel_id": input.TunnelID, "account_id": input.AccountID,
		"idempotency_key": input.IdempotencyKey, "actor_id": input.ActorID,
		"actor_type": input.ActorType, "correlation_id": input.CorrelationID,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%w: %s is required", ErrInvalidInput, name)
		}
	}
	if input.ExpectedGeneration < 1 || input.RequestHash == ([sha256.Size]byte{}) {
		return fmt.Errorf("%w: generation and request hash are required", ErrInvalidInput)
	}
	if !validActorType(input.ActorType) {
		return fmt.Errorf("%w: actor type is invalid", ErrInvalidInput)
	}
	if input.Name == nil && input.AccessMode == nil && !input.ExpirySet {
		return fmt.Errorf("%w: patch must contain a mutable field", ErrInvalidInput)
	}
	if input.Name != nil && strings.TrimSpace(*input.Name) == "" {
		return fmt.Errorf("%w: name cannot be empty", ErrInvalidInput)
	}
	if input.Name != nil {
		if _, err := validateTunnelName(*input.Name); err != nil {
			return err
		}
	}
	if input.AccessMode != nil && *input.AccessMode != AccessPublic && *input.AccessMode != AccessPrivate {
		return fmt.Errorf("%w: access mode is invalid", ErrInvalidInput)
	}
	if input.ExpiresAt != nil && !input.Now.IsZero() && !input.ExpiresAt.After(input.Now.UTC()) {
		return fmt.Errorf("%w: expiry must be in the future", ErrInvalidInput)
	}
	return nil
}

func validateStateRecord(input StateRecord) error {
	for name, value := range map[string]string{
		"operation_id": input.OperationID, "audit_event_id": input.AuditEventID,
		"tunnel_id": input.TunnelID, "account_id": input.AccountID,
		"idempotency_key": input.IdempotencyKey, "actor_id": input.ActorID,
		"actor_type": input.ActorType, "correlation_id": input.CorrelationID,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%w: %s is required", ErrInvalidInput, name)
		}
	}
	if input.ExpectedGeneration < 1 || input.RequestHash == ([sha256.Size]byte{}) {
		return fmt.Errorf("%w: generation and request hash are required", ErrInvalidInput)
	}
	if !validActorType(input.ActorType) {
		return fmt.Errorf("%w: actor type is invalid", ErrInvalidInput)
	}
	switch input.DesiredState {
	case DesiredActive, DesiredPaused, DesiredDeleted:
		return nil
	default:
		return fmt.Errorf("%w: unsupported desired state", ErrInvalidInput)
	}
}

func validateOrigin(origin OriginRequest) error {
	return validateOriginRequest(origin)
}

func nullableString(value string) sql.NullString {
	return sql.NullString{String: value, Valid: strings.TrimSpace(value) != ""}
}

func actorUserID(actorType, actorID string) sql.NullString {
	if actorType != "user" {
		return sql.NullString{}
	}
	return nullableString(actorID)
}

// auditActorID permits a host mutation to retain the authenticated user as
// created_by_actor_id while attributing its audit event to the verified host.
// Records constructed by older callers fall back to ActorID.
func auditActorID(actorID, explicit string) string {
	if strings.TrimSpace(explicit) != "" {
		return explicit
	}
	return actorID
}

func validActorType(actorType string) bool {
	switch actorType {
	case "user", "host", "system", "edge":
		return true
	default:
		return false
	}
}

func translate(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505":
			if strings.Contains(pgErr.ConstraintName, "tunnels_account_id_name") {
				return fmt.Errorf("%w: %s", ErrNameConflict, pgErr.ConstraintName)
			}
			if strings.Contains(pgErr.ConstraintName, "tunnel_routes_tunnel_id_name") || strings.Contains(pgErr.ConstraintName, "tunnel_routes_id_tunnel") {
				return fmt.Errorf("%w: %s", ErrRouteConflict, pgErr.ConstraintName)
			}
			if strings.Contains(pgErr.ConstraintName, "tunnel_domains_hostname") {
				return fmt.Errorf("%w: %s", ErrDomainConflict, pgErr.ConstraintName)
			}
			if strings.Contains(pgErr.ConstraintName, "tunnel_connectors_tunnel_id_host_id") || strings.Contains(pgErr.ConstraintName, "tunnel_connectors_credential") || strings.Contains(pgErr.ConstraintName, "tunnel_connector_credentials") {
				return fmt.Errorf("%w: %s", ErrConnectorConflict, pgErr.ConstraintName)
			}
			if strings.Contains(pgErr.ConstraintName, "tunnel_connector_enrollments_token_hash") {
				return fmt.Errorf("%w: %s", ErrEnrollmentReplay, pgErr.ConstraintName)
			}
			return fmt.Errorf("%w: %s", ErrConflict, pgErr.ConstraintName)
		case "23503", "23514", "23502":
			return fmt.Errorf("%w: %s", ErrInvalidInput, pgErr.ConstraintName)
		}
	}
	return err
}

func newRouteID(tunnelID string) string {
	// Route IDs are opaque to callers, but retaining the complete durable tunnel
	// identity makes the deterministic child key collision-free for generated
	// tunnel IDs and searchable in incident logs.
	return "rte_" + tunnelID + "_default"
}
