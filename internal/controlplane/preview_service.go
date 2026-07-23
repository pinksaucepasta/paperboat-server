package controlplane

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
)

var (
	ErrPreviewInvalid        = errors.New("preview request is invalid")
	ErrPreviewDenied         = errors.New("preview is unavailable")
	ErrPreviewConflict       = errors.New("preview operation conflicts with an earlier request")
	ErrPreviewAcknowledgment = errors.New("public preview acknowledgement is required")
	ErrPreviewRemoved        = errors.New("preview identity has been removed")
)

const previewRetention = 30 * 24 * time.Hour

type PreviewService struct {
	store       *db.DB
	audit       *audit.Writer
	identityKey []byte
	baseDomain  string
	clock       func() time.Time
}

type OwnedPreview struct {
	Preview         dbsqlc.ControlPreview
	ProjectID       string
	MachineID       sql.NullString
	UserID          sql.NullString
	EnvironmentName string
	EnvironmentKind string
	OwnerEmail      string
}

type PreviewObservation struct {
	EnvironmentID string
	PreviewKey    string
	LogicalName   string
	TargetHost    string
	TargetPort    int32
	Revision      uint64
	HelperReady   bool
	TargetReady   bool
	ObservedAt    time.Time
}

func (s *PreviewService) ObserveForHelper(ctx context.Context, observation PreviewObservation) (dbsqlc.ControlPreview, error) {
	if strings.TrimSpace(observation.EnvironmentID) == "" || strings.TrimSpace(observation.PreviewKey) == "" || strings.TrimSpace(observation.LogicalName) == "" || observation.TargetHost != "127.0.0.1" && observation.TargetHost != "::1" || observation.TargetPort < 1 || observation.TargetPort > 65535 || observation.Revision == 0 || observation.ObservedAt.IsZero() {
		return dbsqlc.ControlPreview{}, ErrPreviewInvalid
	}
	if observation.ObservedAt.After(s.clock().Add(time.Minute)) || observation.ObservedAt.Before(s.clock().Add(-10*time.Minute)) {
		return dbsqlc.ControlPreview{}, ErrPreviewInvalid
	}
	return s.store.Queries().ApplyControlPreviewHelperObservation(ctx, dbsqlc.ApplyControlPreviewHelperObservationParams{EnvironmentID: observation.EnvironmentID, PreviewKey: observation.PreviewKey, LogicalName: observation.LogicalName, TargetHost: observation.TargetHost, TargetPort: observation.TargetPort, ObservationRevision: int64(observation.Revision), HelperReady: observation.HelperReady, TargetReady: observation.TargetReady, ObservedAt: sql.NullTime{Time: observation.ObservedAt.UTC(), Valid: true}})
}

func (s *PreviewService) RefreshEdgeReadiness(ctx context.Context) error {
	return s.store.Queries().RefreshControlPreviewEdgeReadiness(ctx, s.clock().UTC())
}

func (s *PreviewService) CanIssueCertificate(ctx context.Context, publicHost string) (bool, error) {
	publicHost = strings.TrimSpace(publicHost)
	if publicHost == "" || len(publicHost) > 253 || strings.ToLower(publicHost) != publicHost || strings.ContainsAny(publicHost, "\x00:/") {
		return false, nil
	}
	return s.store.Queries().CanIssueControlRouteCertificate(ctx, dbsqlc.CanIssueControlRouteCertificateParams{PublicHost: publicHost, Now: sql.NullTime{Time: s.clock().UTC(), Valid: true}})
}

func NewPreviewService(store *db.DB, writer *audit.Writer, identityKey []byte, baseDomain string) (*PreviewService, error) {
	probe, err := PreviewIdentity(identityKey, "environment", "preview", 0)
	if err != nil {
		return nil, err
	}
	if _, err := PreviewHostname(baseDomain, probe); err != nil {
		return nil, err
	}
	return &PreviewService{store: store, audit: writer, identityKey: append([]byte(nil), identityKey...), baseDomain: baseDomain, clock: func() time.Time { return time.Now().UTC() }}, nil
}

func (s *PreviewService) List(ctx context.Context, userID, environmentID string) ([]dbsqlc.ControlPreview, error) {
	if userID == "" || environmentID == "" || !s.ownsEnvironment(ctx, userID, environmentID) {
		return nil, ErrPreviewDenied
	}
	return s.store.Queries().ListControlPreviews(ctx, environmentID)
}

func (s *PreviewService) ListForHelper(ctx context.Context, helperID, environmentID string) ([]dbsqlc.ControlPreview, error) {
	if !s.helperOwnsEnvironment(ctx, helperID, environmentID) {
		return nil, ErrPreviewDenied
	}
	return s.store.Queries().ListControlPreviews(ctx, environmentID)
}

func (s *PreviewService) ListOwned(ctx context.Context, userID string) ([]OwnedPreview, error) {
	if strings.TrimSpace(userID) == "" {
		return nil, ErrPreviewDenied
	}
	rows, err := s.store.Queries().ListOwnedControlPreviews(ctx, sql.NullString{String: userID, Valid: true})
	if err != nil {
		return nil, err
	}
	items := make([]OwnedPreview, 0, len(rows))
	for _, row := range rows {
		items = append(items, OwnedPreview{
			Preview:         dbsqlc.ControlPreview{ID: row.ID, EnvironmentID: row.EnvironmentID, LogicalName: row.LogicalName, PreviewKey: row.PreviewKey, CollisionCounter: row.CollisionCounter, PublicHost: row.PublicHost, TargetHost: row.TargetHost, TargetPort: row.TargetPort, State: row.State, RouteID: row.RouteID, HelperReady: row.HelperReady, EdgeReady: row.EdgeReady, TargetReady: row.TargetReady, PublicAcknowledgedAt: row.PublicAcknowledgedAt, ExpiresAt: row.ExpiresAt, RemovedAt: row.RemovedAt, RetainedUntil: row.RetainedUntil, Version: row.Version, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt},
			ProjectID:       row.WorkspaceID,
			MachineID:       row.MachineID,
			UserID:          row.OwnerUserID,
			EnvironmentName: row.EnvironmentName,
			EnvironmentKind: row.EnvironmentKind,
			OwnerEmail:      row.OwnerEmail,
		})
	}
	return items, nil
}

func (s *PreviewService) RevokeOwned(ctx context.Context, userID, operationKey, previewID string) (dbsqlc.ControlPreview, error) {
	if strings.TrimSpace(userID) == "" || strings.TrimSpace(previewID) == "" {
		return dbsqlc.ControlPreview{}, ErrPreviewDenied
	}
	preview, err := s.store.Queries().GetOwnedControlPreview(ctx, dbsqlc.GetOwnedControlPreviewParams{ID: previewID, OwnerUserID: sql.NullString{String: userID, Valid: true}})
	if err != nil || preview.State == "removed" {
		return dbsqlc.ControlPreview{}, ErrPreviewDenied
	}
	return s.Remove(ctx, userID, operationKey, preview.EnvironmentID, preview.LogicalName)
}

func (s *PreviewService) CreateOrUpdate(ctx context.Context, userID, operationKey, environmentID, logicalName, targetHost string, targetPort int32, acknowledgePublic bool) (dbsqlc.ControlPreview, error) {
	return s.createOrUpdate(ctx, userID, operationKey, environmentID, logicalName, targetHost, targetPort, acknowledgePublic, true)
}

func (s *PreviewService) CreateOrUpdateForHelper(ctx context.Context, helperID, operationID, environmentID, logicalName, targetHost string, targetPort int32, acknowledgePublic bool) (dbsqlc.ControlPreview, error) {
	if strings.TrimSpace(operationID) == "" || !s.helperOwnsEnvironment(ctx, helperID, environmentID) {
		return dbsqlc.ControlPreview{}, ErrPreviewDenied
	}
	return s.createOrUpdate(ctx, helperID, "helper-preview:"+helperID+":"+operationID, environmentID, logicalName, targetHost, targetPort, acknowledgePublic, false)
}

func (s *PreviewService) createOrUpdate(ctx context.Context, actorID, operationKey, environmentID, logicalName, targetHost string, targetPort int32, acknowledgePublic, enforceUserOwnership bool) (dbsqlc.ControlPreview, error) {
	logicalName = strings.TrimSpace(logicalName)
	if actorID == "" || operationKey == "" || environmentID == "" || logicalName == "" || targetHost != "127.0.0.1" && targetHost != "::1" || targetPort < 1 || targetPort > 65535 {
		return dbsqlc.ControlPreview{}, ErrPreviewInvalid
	}
	if enforceUserOwnership && !s.ownsEnvironment(ctx, actorID, environmentID) {
		return dbsqlc.ControlPreview{}, ErrPreviewDenied
	}
	hash := routeRequestHash("preview-upsert", environmentID, logicalName, targetHost, targetPort, acknowledgePublic)
	var result dbsqlc.ControlPreview
	err := s.store.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		if replay, ok, err := previewReplay(ctx, tx, operationKey, "upsert", hash); err != nil || ok {
			if err == nil {
				err = json.Unmarshal(replay, &result)
			}
			return err
		}
		reserved, err := tx.Queries().ReserveControlPreviewOperation(ctx, dbsqlc.ReserveControlPreviewOperationParams{OperationKey: operationKey, OperationType: "upsert", RequestHash: hash[:], PreviewID: sql.NullString{}})
		if err != nil {
			return err
		}
		if reserved.OperationType != "upsert" || !bytes.Equal(reserved.RequestHash, hash[:]) {
			return ErrPreviewConflict
		}
		if len(reserved.Result) > 0 && !bytes.Equal(reserved.Result, []byte("{}")) {
			return json.Unmarshal(reserved.Result, &result)
		}
		current, err := tx.Queries().GetControlPreviewForUpdate(ctx, dbsqlc.GetControlPreviewForUpdateParams{EnvironmentID: environmentID, LogicalName: logicalName})
		if err == nil {
			if current.State == "removed" {
				return ErrPreviewRemoved
			}
			result, err = tx.Queries().UpdateControlPreview(ctx, dbsqlc.UpdateControlPreviewParams{TargetHost: targetHost, TargetPort: targetPort, PublicAcknowledgedAt: acknowledgedAt(acknowledgePublic, s.clock()), Now: s.clock(), ID: current.ID, ExpectedVersion: current.Version})
			if err != nil {
				return err
			}
			if current.RouteID.Valid {
				if _, err = tx.Queries().UpdateControlPreviewRouteTarget(ctx, dbsqlc.UpdateControlPreviewRouteTargetParams{TargetHost: targetHost, TargetPort: targetPort, Now: s.clock(), ID: current.RouteID.String, EnvironmentID: environmentID}); err != nil {
					return err
				}
			}
		} else if !errors.Is(err, sql.ErrNoRows) {
			return err
		} else {
			if !acknowledgePublic {
				return ErrPreviewAcknowledgment
			}
			result, err = s.createIdentity(ctx, tx, environmentID, logicalName, targetHost, targetPort)
			if err != nil {
				return err
			}
		}
		payload, _ := json.Marshal(result)
		if err = tx.Queries().SetControlPreviewOperationResult(ctx, dbsqlc.SetControlPreviewOperationResultParams{Result: payload, PreviewID: sql.NullString{String: result.ID, Valid: true}, OperationKey: operationKey}); err != nil {
			return err
		}
		return s.writeAudit(ctx, tx, actorID, operationKey, "preview.registered", result)
	})
	return result, err
}

func (s *PreviewService) Remove(ctx context.Context, userID, operationKey, environmentID, logicalName string) (dbsqlc.ControlPreview, error) {
	return s.remove(ctx, userID, operationKey, environmentID, logicalName, true)
}

func (s *PreviewService) RemoveForHelper(ctx context.Context, helperID, operationID, environmentID, logicalName string) (dbsqlc.ControlPreview, error) {
	if strings.TrimSpace(operationID) == "" || !s.helperOwnsEnvironment(ctx, helperID, environmentID) {
		return dbsqlc.ControlPreview{}, ErrPreviewDenied
	}
	return s.remove(ctx, helperID, "helper-preview:"+helperID+":"+operationID, environmentID, logicalName, false)
}

func (s *PreviewService) helperOwnsEnvironment(ctx context.Context, helperID, environmentID string) bool {
	if strings.TrimSpace(helperID) == "" || strings.TrimSpace(environmentID) == "" {
		return false
	}
	_, err := s.store.Queries().GetActiveControlHelper(ctx, dbsqlc.GetActiveControlHelperParams{ID: helperID, EnvironmentID: environmentID})
	return err == nil
}

func (s *PreviewService) remove(ctx context.Context, actorID, operationKey, environmentID, logicalName string, enforceUserOwnership bool) (dbsqlc.ControlPreview, error) {
	if actorID == "" || operationKey == "" || environmentID == "" || strings.TrimSpace(logicalName) == "" || enforceUserOwnership && !s.ownsEnvironment(ctx, actorID, environmentID) {
		return dbsqlc.ControlPreview{}, ErrPreviewDenied
	}
	hash := routeRequestHash("preview-remove", environmentID, logicalName)
	var result dbsqlc.ControlPreview
	err := s.store.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		if replay, ok, err := previewReplay(ctx, tx, operationKey, "remove", hash); err != nil || ok {
			if err == nil {
				err = json.Unmarshal(replay, &result)
			}
			return err
		}
		reserved, err := tx.Queries().ReserveControlPreviewOperation(ctx, dbsqlc.ReserveControlPreviewOperationParams{OperationKey: operationKey, OperationType: "remove", RequestHash: hash[:], PreviewID: sql.NullString{}})
		if err != nil {
			return err
		}
		if reserved.OperationType != "remove" || !bytes.Equal(reserved.RequestHash, hash[:]) {
			return ErrPreviewConflict
		}
		if len(reserved.Result) > 0 && !bytes.Equal(reserved.Result, []byte("{}")) {
			return json.Unmarshal(reserved.Result, &result)
		}
		current, err := tx.Queries().GetControlPreviewForUpdate(ctx, dbsqlc.GetControlPreviewForUpdateParams{EnvironmentID: environmentID, LogicalName: logicalName})
		if err != nil || current.State == "removed" {
			return ErrPreviewDenied
		}
		now := s.clock()
		result, err = tx.Queries().RemoveControlPreview(ctx, dbsqlc.RemoveControlPreviewParams{Now: now, RetainedUntil: sql.NullTime{Time: now.Add(previewRetention), Valid: true}, ID: current.ID, ExpectedVersion: current.Version})
		if err != nil {
			return err
		}
		if current.RouteID.Valid {
			if _, err = tx.Queries().RemoveControlPreviewRoute(ctx, dbsqlc.RemoveControlPreviewRouteParams{Now: now, ID: current.RouteID.String, EnvironmentID: environmentID}); err != nil {
				return err
			}
		}
		payload, _ := json.Marshal(result)
		if err = tx.Queries().SetControlPreviewOperationResult(ctx, dbsqlc.SetControlPreviewOperationResultParams{Result: payload, PreviewID: sql.NullString{String: result.ID, Valid: true}, OperationKey: operationKey}); err != nil {
			return err
		}
		return s.writeAudit(ctx, tx, actorID, operationKey, "preview.removed", result)
	})
	return result, err
}

func (s *PreviewService) createIdentity(ctx context.Context, tx *db.Tx, environmentID, logicalName, targetHost string, targetPort int32) (dbsqlc.ControlPreview, error) {
	previewID, err := randomHex("prv_", 12)
	if err != nil {
		return dbsqlc.ControlPreview{}, err
	}
	routeID, err := randomHex("route_", 12)
	if err != nil {
		return dbsqlc.ControlPreview{}, err
	}
	for counter := uint64(0); counter < 16; counter++ {
		key, err := PreviewIdentity(s.identityKey, environmentID, logicalName, counter)
		if err != nil {
			return dbsqlc.ControlPreview{}, err
		}
		host, err := PreviewHostname(s.baseDomain, key)
		if err != nil {
			return dbsqlc.ControlPreview{}, err
		}
		preview, err := tx.Queries().CreateControlPreview(ctx, dbsqlc.CreateControlPreviewParams{ID: previewID, EnvironmentID: environmentID, LogicalName: logicalName, PreviewKey: key, CollisionCounter: int64(counter), PublicHost: host, TargetHost: targetHost, TargetPort: targetPort, PublicAcknowledgedAt: acknowledgedAt(true, s.clock())})
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return dbsqlc.ControlPreview{}, err
		}
		if _, err = tx.Queries().CreateControlRoute(ctx, dbsqlc.CreateControlRouteParams{ID: routeID, EnvironmentID: environmentID, Kind: "preview_public_https_wss", PublicHost: host, TargetHost: targetHost, TargetPort: targetPort}); err != nil {
			return dbsqlc.ControlPreview{}, err
		}
		return tx.Queries().SetControlPreviewRoute(ctx, dbsqlc.SetControlPreviewRouteParams{RouteID: sql.NullString{String: routeID, Valid: true}, Now: s.clock(), ID: preview.ID})
	}
	return dbsqlc.ControlPreview{}, fmt.Errorf("%w: collision limit reached", ErrPreviewConflict)
}

func previewReplay(ctx context.Context, tx *db.Tx, operationKey, operationType string, hash [32]byte) ([]byte, bool, error) {
	op, err := tx.Queries().GetControlPreviewOperation(ctx, operationKey)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if op.OperationType != operationType || !bytes.Equal(op.RequestHash, hash[:]) {
		return nil, false, ErrPreviewConflict
	}
	if len(op.Result) == 0 || bytes.Equal(op.Result, []byte("{}")) {
		return nil, false, ErrPreviewConflict
	}
	return op.Result, true, nil
}

func acknowledgedAt(ok bool, now time.Time) sql.NullTime { return sql.NullTime{Time: now, Valid: ok} }

func (s *PreviewService) ownsEnvironment(ctx context.Context, userID, environmentID string) bool {
	environment, err := s.store.Queries().GetControlEnvironment(ctx, environmentID)
	return err == nil && environment.OwnerUserID.Valid && environment.OwnerUserID.String == userID && environment.DesiredState == "active" && !environment.RevokedAt.Valid
}

func (s *PreviewService) writeAudit(ctx context.Context, tx *db.Tx, userID, operationKey, eventType string, preview dbsqlc.ControlPreview) error {
	if s.audit == nil {
		return nil
	}
	event := audit.Event{ActorType: audit.ActorUser, EventType: eventType, ResourceType: "preview", ResourceID: preview.ID, IdempotencyKey: operationKey, Metadata: map[string]any{"environment_id": preview.EnvironmentID, "logical_name": preview.LogicalName, "state": preview.State}}
	if strings.HasPrefix(operationKey, "helper-preview:") {
		event.ActorType = audit.ActorSystem
		userID = ""
	}
	event.ActorUserID = userID
	return s.audit.WriteTx(ctx, tx, event)
}
