package controlplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
)

var (
	ErrRouteInvalid  = errors.New("route intent is invalid")
	ErrRouteConflict = errors.New("route intent version conflict")
	ErrRouteDenied   = errors.New("route intent is unavailable")
)

type RouteService struct {
	store *db.DB
	audit *audit.Writer
	clock func() time.Time
}

func NewRouteService(store *db.DB, writer *audit.Writer) *RouteService {
	return &RouteService{store: store, audit: writer, clock: func() time.Time { return time.Now().UTC() }}
}

func (s *RouteService) Create(ctx context.Context, userID, operationKey, environmentID, kind, publicHost, targetHost string, targetPort int32) (dbsqlc.ControlRoute, error) {
	publicHost = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(publicHost), "."))
	if userID == "" || operationKey == "" || environmentID == "" || !validRouteKind(kind) || !validRouteHost(publicHost) || (targetHost != "127.0.0.1" && targetHost != "::1") || targetPort < 1 || targetPort > 65535 {
		return dbsqlc.ControlRoute{}, ErrRouteInvalid
	}
	if !s.ownsEnvironment(ctx, userID, environmentID) {
		return dbsqlc.ControlRoute{}, ErrRouteDenied
	}
	id, err := randomHex("route_", 12)
	if err != nil {
		return dbsqlc.ControlRoute{}, err
	}
	hash := routeRequestHash("create", environmentID, kind, publicHost, targetHost, targetPort)
	var route dbsqlc.ControlRoute
	err = s.store.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		existing, getErr := tx.Queries().GetControlRouteOperation(ctx, operationKey)
		if getErr == nil {
			if existing.OperationType != "create" || !bytes.Equal(existing.RequestHash, hash[:]) {
				return ErrRouteConflict
			}
			return json.Unmarshal(existing.Result, &route)
		}
		if !errors.Is(getErr, sql.ErrNoRows) {
			return getErr
		}
		reserved, err := tx.Queries().ReserveControlRouteOperation(ctx, dbsqlc.ReserveControlRouteOperationParams{OperationKey: operationKey, OperationType: "create", RequestHash: hash[:], RouteID: id})
		if err != nil {
			return err
		}
		if reserved.OperationType != "create" || !bytes.Equal(reserved.RequestHash, hash[:]) {
			return ErrRouteConflict
		}
		if reserved.ResultRevision.Valid {
			return json.Unmarshal(reserved.Result, &route)
		}
		route, err = tx.Queries().CreateControlRoute(ctx, dbsqlc.CreateControlRouteParams{ID: id, EnvironmentID: environmentID, Kind: kind, PublicHost: publicHost, TargetHost: targetHost, TargetPort: targetPort})
		if err != nil {
			return err
		}
		result, _ := json.Marshal(route)
		if _, err = tx.Queries().SetControlRouteOperationResult(ctx, dbsqlc.SetControlRouteOperationResultParams{OperationKey: operationKey, ResultRevision: sql.NullInt64{Int64: route.DesiredRevision, Valid: true}, Result: result}); err != nil {
			return err
		}
		return s.audit.WriteTx(ctx, tx, audit.Event{ActorUserID: userID, ActorType: audit.ActorUser, EventType: "route.intent_created", ResourceType: "route", ResourceID: id, IdempotencyKey: operationKey, Metadata: map[string]any{"environment_id": environmentID, "kind": kind}})
	})
	if errors.Is(err, sql.ErrNoRows) {
		return dbsqlc.ControlRoute{}, ErrRouteConflict
	}
	return route, err
}

func (s *RouteService) Transition(ctx context.Context, userID, operationKey, routeID, state string, expectedRevision int64) (dbsqlc.ControlRoute, error) {
	if userID == "" || operationKey == "" || routeID == "" || expectedRevision < 1 || (state != "attached" && state != "detaching" && state != "detached" && state != "replacing") {
		return dbsqlc.ControlRoute{}, ErrRouteInvalid
	}
	current, err := s.store.Queries().GetControlRouteForUpdate(ctx, routeID)
	if err != nil || !s.ownsEnvironment(ctx, userID, current.EnvironmentID) {
		return dbsqlc.ControlRoute{}, ErrRouteDenied
	}
	hash := routeRequestHash("transition", routeID, state, expectedRevision)
	var route dbsqlc.ControlRoute
	err = s.store.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		existing, getErr := tx.Queries().GetControlRouteOperation(ctx, operationKey)
		if getErr == nil {
			if existing.OperationType != "transition" || !bytes.Equal(existing.RequestHash, hash[:]) {
				return ErrRouteConflict
			}
			return json.Unmarshal(existing.Result, &route)
		}
		if !errors.Is(getErr, sql.ErrNoRows) {
			return getErr
		}
		reserved, err := tx.Queries().ReserveControlRouteOperation(ctx, dbsqlc.ReserveControlRouteOperationParams{OperationKey: operationKey, OperationType: "transition", RequestHash: hash[:], RouteID: routeID})
		if err != nil {
			return err
		}
		if reserved.OperationType != "transition" || reserved.RouteID != routeID || !bytes.Equal(reserved.RequestHash, hash[:]) {
			return ErrRouteConflict
		}
		if reserved.ResultRevision.Valid {
			return json.Unmarshal(reserved.Result, &route)
		}
		route, err = tx.Queries().AdvanceControlRouteRevision(ctx, dbsqlc.AdvanceControlRouteRevisionParams{ID: routeID, DesiredState: state, ExpectedRevision: expectedRevision, Now: s.clock().UTC()})
		if err != nil {
			return err
		}
		result, _ := json.Marshal(route)
		if _, err = tx.Queries().SetControlRouteOperationResult(ctx, dbsqlc.SetControlRouteOperationResultParams{OperationKey: operationKey, ResultRevision: sql.NullInt64{Int64: route.DesiredRevision, Valid: true}, Result: result}); err != nil {
			return err
		}
		return s.audit.WriteTx(ctx, tx, audit.Event{ActorUserID: userID, ActorType: audit.ActorUser, EventType: "route.intent_transitioned", ResourceType: "route", ResourceID: routeID, IdempotencyKey: operationKey, Metadata: map[string]any{"desired_state": state}})
	})
	if errors.Is(err, sql.ErrNoRows) {
		return dbsqlc.ControlRoute{}, ErrRouteConflict
	}
	if err != nil {
		return dbsqlc.ControlRoute{}, err
	}
	return route, nil
}

func routeRequestHash(values ...any) [32]byte {
	data, _ := json.Marshal(values)
	return sha256.Sum256(data)
}
func validRouteKind(kind string) bool {
	return kind == "helper_https_wss" || kind == "preview_public_https_wss"
}
func validRouteHost(host string) bool {
	host = strings.TrimSpace(host)
	return host != "" && len(host) <= 253 && net.ParseIP(host) == nil && !strings.ContainsAny(host, "/: ")
}
func (s *RouteService) ownsEnvironment(ctx context.Context, userID, environmentID string) bool {
	env, err := s.store.Queries().GetControlEnvironment(ctx, environmentID)
	return err == nil && env.OwnerUserID.Valid && env.OwnerUserID.String == userID && env.DesiredState == "active"
}
