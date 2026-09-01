package tunnelv1

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/pinksaucepasta/paperboat-server/internal/connectorprotocol"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
	"github.com/pinksaucepasta/paperboat-server/internal/previewtunnelapi"
)

func (r *SQLRepository) ListResourceRoutes(ctx context.Context, accountID, tunnelID string, after *ListPosition, limit int) ([]dbsqlc.TunnelRoute, error) {
	if strings.TrimSpace(accountID) == "" || strings.TrimSpace(tunnelID) == "" || limit < 1 || limit > previewtunnelapi.MaximumPageLimit+1 {
		return nil, ErrInvalidInput
	}
	createdAt, id := resourceAfter(after)
	rows, err := r.db.Queries().ListTunnelRoutesV1(ctx, dbsqlc.ListTunnelRoutesV1Params{
		AccountID: accountID, TunnelID: tunnelID, AfterCreatedAt: createdAt, AfterID: id, RowLimit: int32(limit),
	})
	return rows, translate(err)
}

func (r *SQLRepository) GetResourceRoute(ctx context.Context, accountID, tunnelID, routeID string) (dbsqlc.TunnelRoute, error) {
	if strings.TrimSpace(accountID) == "" || strings.TrimSpace(tunnelID) == "" || strings.TrimSpace(routeID) == "" {
		return dbsqlc.TunnelRoute{}, ErrInvalidInput
	}
	row, err := r.db.Queries().GetTunnelRouteV1(ctx, dbsqlc.GetTunnelRouteV1Params{
		RouteID: routeID, TunnelID: tunnelID, AccountID: accountID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return dbsqlc.TunnelRoute{}, ErrRouteNotFound
	}
	return row, translate(err)
}

func (r *SQLRepository) CreateResourceRoute(ctx context.Context, input RouteRecord) (ResourceMutationRecord, error) {
	if err := validateRouteRecord(input, false); err != nil {
		return ResourceMutationRecord{}, err
	}
	var result ResourceMutationRecord
	err := r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := tx.Queries()
		tunnel, err := q.GetTunnelForResourceV1(ctx, dbsqlc.GetTunnelForResourceV1Params{TunnelID: input.TunnelID, AccountID: input.AccountID})
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return translate(err)
		}
		if tunnel.DesiredState == DesiredDeleted {
			return ErrTerminalState
		}
		candidate := routeCandidate(input)
		if err := validateEffectiveRouteCandidate(tunnel, candidate); err != nil {
			return err
		}
		op, replayed, err := beginResourceOperation(ctx, q, resourceOperationInput{
			ID: input.OperationID, AccountID: input.AccountID, IdempotencyKey: input.IdempotencyKey,
			RequestHash: input.RequestHash, OperationType: "route.create", ResourceKind: "route",
			ResourceID: input.RouteID, CorrelationID: input.CorrelationID,
		})
		if err != nil {
			return err
		}
		if replayed {
			result.Operation = op
			result.Replayed = true
			if op.ResourceID.Valid {
				result.Route, err = q.GetTunnelRouteV1(ctx, dbsqlc.GetTunnelRouteV1Params{RouteID: op.ResourceID.String, TunnelID: input.TunnelID, AccountID: input.AccountID})
				if errors.Is(err, pgx.ErrNoRows) {
					return ErrRouteNotFound
				}
				return translate(err)
			}
			return nil
		}
		conflict, err := q.HasConflictingTunnelRouteV1(ctx, dbsqlc.HasConflictingTunnelRouteV1Params{
			TunnelID: input.TunnelID, ExcludeID: input.RouteID, MatchType: candidate.MatchType,
			PathPrefix: candidate.PathPrefix, MatchHostname: candidate.MatchHostname, WildcardSuffix: candidate.WildcardSuffix,
		})
		if err != nil {
			return translate(err)
		}
		if conflict {
			return ErrRouteConflict
		}
		route, err := q.CreateTunnelRouteV1(ctx, createRouteParams(input))
		if err != nil {
			return translate(err)
		}
		updatedTunnel, err := q.BumpTunnelGenerationForResourceV1(ctx, dbsqlc.BumpTunnelGenerationForResourceV1Params{TunnelID: input.TunnelID, AccountID: input.AccountID, Now: input.Now})
		if err != nil {
			return translate(err)
		}
		if err := createResourceConfigGeneration(ctx, q, updatedTunnel, input.ActorID, input.Now); err != nil {
			return err
		}
		op, err = advanceResourceOperation(ctx, q, op.ID, route.ID, "connecting", 60, input.Now)
		if err != nil {
			return err
		}
		if err := recordResourceChange(ctx, q, resourceAuditInput{
			AuditEventID: input.AuditEventID, ParentAuditEventID: input.ParentAuditEventID,
			AccountID: input.AccountID, ActorID: auditActorID(input.ActorID, input.AuditActorID), ActorType: input.ActorType,
			EventType: "route.created", ParentEventType: "tunnel.route_created", ResourceType: "route", ResourceID: route.ID,
			TunnelID: input.TunnelID, OperationID: op.ID, IdempotencyKey: input.IdempotencyKey, RequestID: input.RequestID,
			CorrelationID: input.CorrelationID, SourceDeviceID: input.SourceDeviceID, Now: input.Now,
			Metadata: routeAuditMetadata(route),
			Message:  routeAuditMessage("route persisted and awaiting connector application", route),
		}); err != nil {
			return err
		}
		result = ResourceMutationRecord{Route: route, Operation: op, Changed: true}
		return nil
	})
	return result, translate(err)
}

func (r *SQLRepository) PatchResourceRoute(ctx context.Context, input RouteRecord) (ResourceMutationRecord, error) {
	if err := validateRouteRecord(input, true); err != nil {
		return ResourceMutationRecord{}, err
	}
	var result ResourceMutationRecord
	err := r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := tx.Queries()
		tunnel, err := q.GetTunnelForResourceV1(ctx, dbsqlc.GetTunnelForResourceV1Params{TunnelID: input.TunnelID, AccountID: input.AccountID})
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return translate(err)
		}
		if tunnel.DesiredState == DesiredDeleted {
			return ErrTerminalState
		}
		op, replayed, err := beginResourceOperation(ctx, q, resourceOperationInput{
			ID: input.OperationID, AccountID: input.AccountID, IdempotencyKey: input.IdempotencyKey,
			RequestHash: input.RequestHash, OperationType: "route.patch", ResourceKind: "route",
			ResourceID: input.RouteID, CorrelationID: input.CorrelationID,
		})
		if err != nil {
			return err
		}
		current, err := q.GetTunnelRouteV1(ctx, dbsqlc.GetTunnelRouteV1Params{RouteID: input.RouteID, TunnelID: input.TunnelID, AccountID: input.AccountID})
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrRouteNotFound
		}
		if err != nil {
			return translate(err)
		}
		if replayed {
			result = ResourceMutationRecord{Route: current, Operation: op, Replayed: true, Changed: op.Outcome == "changed"}
			return nil
		}
		if current.DeletedAt.Valid {
			return ErrTerminalState
		}
		if current.Generation != input.ExpectedGeneration {
			return ErrGenerationConflict
		}
		candidate := routeCandidateFromRecord(current, input)
		if err := validateEffectiveRouteCandidate(tunnel, candidate); err != nil {
			return err
		}
		if input.NameSet || input.ProtocolSet || input.MatchTypeSet || input.HostnameSet || input.WildcardSuffixSet || input.PathPrefixSet || input.OriginSet || input.PrioritySet || input.DesiredStateSet {
			conflict, conflictErr := q.HasConflictingTunnelRouteV1(ctx, dbsqlc.HasConflictingTunnelRouteV1Params{
				TunnelID: input.TunnelID, ExcludeID: current.ID, MatchType: candidate.MatchType,
				PathPrefix: candidate.PathPrefix, MatchHostname: candidate.MatchHostname, WildcardSuffix: candidate.WildcardSuffix,
			})
			if conflictErr != nil {
				return translate(conflictErr)
			}
			if conflict {
				return ErrRouteConflict
			}
		}
		changed := routeRecordChanges(current, input)
		now := input.Now
		if changed {
			updated, updateErr := q.UpdateTunnelRouteV1(ctx, updateRouteParams(input))
			if errors.Is(updateErr, pgx.ErrNoRows) {
				return ErrGenerationConflict
			}
			if updateErr != nil {
				return translate(updateErr)
			}
			current = updated
			tunnel, err = q.BumpTunnelGenerationForResourceV1(ctx, dbsqlc.BumpTunnelGenerationForResourceV1Params{TunnelID: input.TunnelID, AccountID: input.AccountID, Now: now})
			if err != nil {
				return translate(err)
			}
			if err := createResourceConfigGeneration(ctx, q, tunnel, input.ActorID, now); err != nil {
				return err
			}
		}
		outcome := "unchanged"
		if changed {
			outcome = "changed"
		}
		if changed {
			op, err = advanceResourceOperation(ctx, q, op.ID, current.ID, "connecting", 60, now)
		} else {
			op, err = completeResourceOperation(ctx, q, op.ID, current.ID, "ready", outcome, now)
		}
		if err != nil {
			return err
		}
		if err := recordResourceChange(ctx, q, resourceAuditInput{
			AuditEventID: input.AuditEventID, ParentAuditEventID: input.ParentAuditEventID,
			AccountID: input.AccountID, ActorID: auditActorID(input.ActorID, input.AuditActorID), ActorType: input.ActorType,
			EventType: "route.updated", ParentEventType: "tunnel.route_updated", ResourceType: "route", ResourceID: current.ID,
			TunnelID: input.TunnelID, OperationID: op.ID, IdempotencyKey: input.IdempotencyKey, RequestID: input.RequestID,
			CorrelationID: input.CorrelationID, SourceDeviceID: input.SourceDeviceID, Now: now,
			Metadata: routeAuditMetadata(current),
			Message:  routeAuditMessage("route update persisted", current),
		}); err != nil {
			return err
		}
		result = ResourceMutationRecord{Route: current, Operation: op, Changed: changed}
		return nil
	})
	return result, translate(err)
}

func (r *SQLRepository) DeleteResourceRoute(ctx context.Context, input RouteRecord) (ResourceMutationRecord, error) {
	if err := validateRouteRecord(input, true); err != nil {
		return ResourceMutationRecord{}, err
	}
	var result ResourceMutationRecord
	err := r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := tx.Queries()
		_, err := q.GetTunnelForResourceV1(ctx, dbsqlc.GetTunnelForResourceV1Params{TunnelID: input.TunnelID, AccountID: input.AccountID})
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return translate(err)
		}
		op, replayed, err := beginResourceOperation(ctx, q, resourceOperationInput{
			ID: input.OperationID, AccountID: input.AccountID, IdempotencyKey: input.IdempotencyKey,
			RequestHash: input.RequestHash, OperationType: "route.delete", ResourceKind: "route",
			ResourceID: input.RouteID, CorrelationID: input.CorrelationID,
		})
		if err != nil {
			return err
		}
		current, err := q.GetTunnelRouteV1(ctx, dbsqlc.GetTunnelRouteV1Params{RouteID: input.RouteID, TunnelID: input.TunnelID, AccountID: input.AccountID})
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrRouteNotFound
		}
		if err != nil {
			return translate(err)
		}
		if replayed {
			result = ResourceMutationRecord{Route: current, Operation: op, Replayed: true, Changed: op.Outcome == "changed"}
			return nil
		}
		if current.DeletedAt.Valid {
			op, err = completeResourceOperation(ctx, q, op.ID, current.ID, "ready", "unchanged", input.Now)
			if err != nil {
				return err
			}
			result = ResourceMutationRecord{Route: current, Operation: op, Changed: false}
			return nil
		}
		if current.Generation != input.ExpectedGeneration {
			return ErrGenerationConflict
		}
		current, err = q.DeleteTunnelRouteV1(ctx, dbsqlc.DeleteTunnelRouteV1Params{Now: sql.NullTime{Time: input.Now, Valid: true}, ActorID: input.ActorID, RouteID: input.RouteID, TunnelID: input.TunnelID, ExpectedGeneration: input.ExpectedGeneration})
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrGenerationConflict
		}
		if err != nil {
			return translate(err)
		}
		tunnel, err := q.BumpTunnelGenerationForResourceV1(ctx, dbsqlc.BumpTunnelGenerationForResourceV1Params{TunnelID: input.TunnelID, AccountID: input.AccountID, Now: input.Now})
		if err != nil {
			return translate(err)
		}
		if err := createResourceConfigGeneration(ctx, q, tunnel, input.ActorID, input.Now); err != nil {
			return err
		}
		op, err = advanceResourceOperation(ctx, q, op.ID, current.ID, "draining", 60, input.Now)
		if err != nil {
			return err
		}
		if err := recordResourceChange(ctx, q, resourceAuditInput{
			AuditEventID: input.AuditEventID, ParentAuditEventID: input.ParentAuditEventID,
			AccountID: input.AccountID, ActorID: auditActorID(input.ActorID, input.AuditActorID), ActorType: input.ActorType,
			EventType: "route.deleted", ParentEventType: "tunnel.route_deleted", ResourceType: "route", ResourceID: current.ID,
			TunnelID: input.TunnelID, OperationID: op.ID, IdempotencyKey: input.IdempotencyKey, RequestID: input.RequestID,
			CorrelationID: input.CorrelationID, SourceDeviceID: input.SourceDeviceID, Now: input.Now,
			Metadata: map[string]any{"generation": current.Generation}, Message: "route deletion persisted; connector drain pending",
		}); err != nil {
			return err
		}
		result = ResourceMutationRecord{Route: current, Operation: op, Changed: true}
		return nil
	})
	return result, translate(err)
}

func createRouteParams(input RouteRecord) dbsqlc.CreateTunnelRouteV1Params {
	tlsVerification, serverName, caRef, clientRef := routeTLSValues(input.Origin)
	return dbsqlc.CreateTunnelRouteV1Params{
		ID: input.RouteID, TunnelID: input.TunnelID, Name: input.Name, Protocol: input.Protocol,
		MatchType: input.MatchType, MatchHostname: input.Hostname, WildcardSuffix: input.WildcardSuffix,
		PathPrefix: input.PathPrefix, Priority: input.Priority, OriginScheme: input.Origin.Scheme,
		OriginAddress: input.Origin.Address, PreserveHost: input.Origin.PreserveHost, HostOverride: nullableStringPtr(input.Origin.HostOverride),
		TlsVerification: tlsVerification, TlsServerName: nullableStringPtr(serverName), CaReference: nullableStringPtr(caRef),
		MtlsCredentialReference: nullableStringPtr(clientRef), ConnectTimeoutMs: input.ConnectTimeoutMS, IdleTimeoutMs: input.IdleTimeoutMS,
		MaxConcurrentStreams: input.MaxConcurrentStreams, DesiredState: "active", CreatedByActorID: input.ActorID, UpdatedByActorID: input.ActorID, Now: input.Now,
	}
}

func updateRouteParams(input RouteRecord) dbsqlc.UpdateTunnelRouteV1Params {
	tlsVerification, serverName, caRef, clientRef := routeTLSValues(input.Origin)
	return dbsqlc.UpdateTunnelRouteV1Params{
		NameSet: input.NameSet, Name: input.Name, ProtocolSet: input.ProtocolSet, Protocol: input.Protocol,
		MatchTypeSet: input.MatchTypeSet, MatchType: input.MatchType, MatchHostnameSet: input.HostnameSet, MatchHostname: input.Hostname,
		WildcardSuffixSet: input.WildcardSuffixSet, WildcardSuffix: input.WildcardSuffix, PathPrefixSet: input.PathPrefixSet, PathPrefix: input.PathPrefix,
		PrioritySet: input.PrioritySet, Priority: input.Priority, OriginSchemeSet: input.OriginSet, OriginScheme: input.Origin.Scheme,
		OriginAddressSet: input.OriginSet, OriginAddress: input.Origin.Address, PreserveHostSet: input.OriginSet, PreserveHost: input.Origin.PreserveHost,
		HostOverrideSet: input.OriginSet, HostOverride: nullableStringPtr(input.Origin.HostOverride), TlsVerificationSet: input.OriginSet, TlsVerification: tlsVerification,
		TlsServerNameSet: input.OriginSet, TlsServerName: nullableStringPtr(serverName), CaReferenceSet: input.OriginSet, CaReference: nullableStringPtr(caRef),
		MtlsCredentialReferenceSet: input.OriginSet, MtlsCredentialReference: nullableStringPtr(clientRef), DesiredStateSet: input.DesiredStateSet,
		DesiredState: input.DesiredState, UpdatedByActorID: input.ActorID, Now: input.Now, RouteID: input.RouteID, TunnelID: input.TunnelID,
		ExpectedGeneration: input.ExpectedGeneration,
		ConnectTimeoutSet:  input.ConnectTimeoutSet, ConnectTimeoutMs: input.ConnectTimeoutMS,
		IdleTimeoutSet: input.IdleTimeoutSet, IdleTimeoutMs: input.IdleTimeoutMS,
		MaxStreamsSet: input.MaxStreamsSet, MaxConcurrentStreams: input.MaxConcurrentStreams,
	}
}

func nullableStringPtr(value *string) sql.NullString {
	if value == nil {
		return sql.NullString{}
	}
	return nullableString(*value)
}

func resourceAfter(after *ListPosition) (sql.NullTime, sql.NullString) {
	if after == nil {
		return sql.NullTime{}, sql.NullString{}
	}
	return sql.NullTime{Time: after.CreatedAt.UTC(), Valid: true}, nullableString(after.ID)
}

func routeTLSValues(origin RouteOriginRequest) (string, *string, *string, *string) {
	if origin.Scheme != "https" || origin.TLS == nil {
		if origin.Scheme == "https" {
			return "system", nil, nil, nil
		}
		return "not_applicable", nil, nil, nil
	}
	return origin.TLS.Verification, origin.TLS.ServerName, origin.TLS.CAReference, origin.TLS.ClientCredentialReference
}

func routeCandidate(input RouteRecord) dbsqlc.TunnelRoute {
	return dbsqlc.TunnelRoute{ID: input.RouteID, TunnelID: input.TunnelID, Name: input.Name, Protocol: input.Protocol, MatchType: input.MatchType,
		MatchHostname: input.Hostname, WildcardSuffix: input.WildcardSuffix, PathPrefix: input.PathPrefix, Priority: input.Priority,
		OriginScheme: input.Origin.Scheme, OriginAddress: input.Origin.Address, PreserveHost: input.Origin.PreserveHost,
		ConnectTimeoutMs: input.ConnectTimeoutMS, IdleTimeoutMs: input.IdleTimeoutMS, MaxConcurrentStreams: input.MaxConcurrentStreams,
		DesiredState: input.DesiredState}
}

func routeCandidateFromRecord(current dbsqlc.TunnelRoute, input RouteRecord) dbsqlc.TunnelRoute {
	candidate := current
	if input.NameSet {
		candidate.Name = input.Name
	}
	if input.ProtocolSet {
		candidate.Protocol = input.Protocol
	}
	if input.MatchTypeSet {
		candidate.MatchType = input.MatchType
	}
	if input.HostnameSet {
		candidate.MatchHostname = input.Hostname
	}
	if input.WildcardSuffixSet {
		candidate.WildcardSuffix = input.WildcardSuffix
	}
	if input.PathPrefixSet {
		candidate.PathPrefix = input.PathPrefix
	}
	if input.OriginSet {
		candidate.OriginScheme = input.Origin.Scheme
		candidate.OriginAddress = input.Origin.Address
		candidate.PreserveHost = input.Origin.PreserveHost
		candidate.HostOverride = nullableStringPtr(input.Origin.HostOverride)
		candidate.TlsVerification, candidate.TlsServerName, candidate.CaReference, candidate.MtlsCredentialReference = routeTLSNullValues(input.Origin)
	}
	if input.PrioritySet {
		candidate.Priority = input.Priority
	}
	if input.ConnectTimeoutSet {
		candidate.ConnectTimeoutMs = input.ConnectTimeoutMS
	}
	if input.IdleTimeoutSet {
		candidate.IdleTimeoutMs = input.IdleTimeoutMS
	}
	if input.MaxStreamsSet {
		candidate.MaxConcurrentStreams = input.MaxConcurrentStreams
	}
	if input.DesiredStateSet {
		candidate.DesiredState = input.DesiredState
	}
	return candidate
}

// validateEffectiveRouteCandidate validates the merged post-mutation route,
// rather than only fields present in a PATCH body. This keeps protocol,
// tunnel-access, host-match, and origin semantics atomic across partial
// updates.
func validateEffectiveRouteCandidate(tunnel dbsqlc.Tunnel, candidate dbsqlc.TunnelRoute) error {
	if candidate.Protocol == "private_tcp" {
		if tunnel.AccessMode != AccessPrivate || candidate.OriginScheme != "tcp" {
			return fmt.Errorf("%w: tcp_private routes require a private tunnel and tcp origin", ErrInvalidInput)
		}
		if candidate.MatchType != "catch_all" || candidate.MatchHostname.Valid || candidate.WildcardSuffix.Valid || candidate.PathPrefix.Valid {
			return fmt.Errorf("%w: tcp_private routes require a catch-all host match without a path prefix", ErrInvalidInput)
		}
	}
	if candidate.Protocol == "http" && candidate.OriginScheme == "tcp" {
		return fmt.Errorf("%w: HTTP routes cannot target a tcp origin", ErrInvalidInput)
	}
	if candidate.MatchType == "catch_all" && (candidate.MatchHostname.Valid || candidate.WildcardSuffix.Valid) {
		return fmt.Errorf("%w: catch-all routes cannot include a hostname", ErrInvalidInput)
	}
	return nil
}

func nullStringValue(value sql.NullString) string {
	if value.Valid {
		return value.String
	}
	return ""
}

func routeRecordChanges(current dbsqlc.TunnelRoute, input RouteRecord) bool {
	candidate := routeCandidateFromRecord(current, input)
	return current.Name != candidate.Name || current.Protocol != candidate.Protocol || current.MatchType != candidate.MatchType ||
		current.MatchHostname != candidate.MatchHostname || current.WildcardSuffix != candidate.WildcardSuffix || current.PathPrefix != candidate.PathPrefix ||
		current.Priority != candidate.Priority || current.OriginScheme != candidate.OriginScheme || current.OriginAddress != candidate.OriginAddress ||
		current.PreserveHost != candidate.PreserveHost || current.HostOverride != candidate.HostOverride || current.TlsVerification != candidate.TlsVerification ||
		current.TlsServerName != candidate.TlsServerName || current.CaReference != candidate.CaReference || current.MtlsCredentialReference != candidate.MtlsCredentialReference ||
		current.ConnectTimeoutMs != candidate.ConnectTimeoutMs || current.IdleTimeoutMs != candidate.IdleTimeoutMs || current.MaxConcurrentStreams != candidate.MaxConcurrentStreams ||
		current.DesiredState != candidate.DesiredState
}

func routeTLSNullValues(origin RouteOriginRequest) (string, sql.NullString, sql.NullString, sql.NullString) {
	verification, serverName, caReference, clientReference := routeTLSValues(origin)
	return verification, nullableStringPtr(serverName), nullableStringPtr(caReference), nullableStringPtr(clientReference)
}

func routeAuditMetadata(route dbsqlc.TunnelRoute) map[string]any {
	return map[string]any{
		"generation": route.Generation, "protocol": wireProtocol(route.Protocol), "origin_scheme": route.OriginScheme,
		"desired_state": route.DesiredState, "origin_tls_verification": route.TlsVerification,
		"origin_tls_insecure_development": route.TlsVerification == "insecure_development",
	}
}

func routeAuditMessage(message string, route dbsqlc.TunnelRoute) string {
	if route.TlsVerification == "insecure_development" {
		return message + "; warning: origin TLS certificate verification is disabled for development"
	}
	return message
}

func createResourceConfigGeneration(ctx context.Context, q *dbsqlc.Queries, tunnel dbsqlc.Tunnel, actorID string, now time.Time) error {
	if tunnel.Generation > 1 {
		if _, err := q.GetTunnelConfigGenerationV1(ctx, dbsqlc.GetTunnelConfigGenerationV1Params{TunnelID: tunnel.ID, Generation: tunnel.Generation - 1}); errors.Is(err, pgx.ErrNoRows) {
			return ErrConfigGenerationChain
		} else if err != nil {
			return translate(err)
		}
	}
	routes, err := q.ListActiveTunnelRoutesForSnapshotV1(ctx, tunnel.ID)
	if err != nil {
		return translate(err)
	}
	snapshot, err := resourceConfigSnapshot(tunnel, routes)
	if err != nil {
		return err
	}
	hash := sha256.Sum256(snapshot)
	previous := sql.NullInt64{Int64: tunnel.Generation - 1, Valid: tunnel.Generation > 1}
	_, err = q.CreatePreviewTunnelConfigGeneration(ctx, dbsqlc.CreatePreviewTunnelConfigGenerationParams{
		TunnelID: tunnel.ID, Generation: tunnel.Generation, PreviousGeneration: previous, ContentHash: hash[:], Snapshot: snapshot,
		ActivationState: "pending", CreatedByActorID: actorID, Now: now, RetainedUntil: now.Add(configGenerationRetention),
	})
	return translate(err)
}

func resourceConfigSnapshot(tunnel dbsqlc.Tunnel, routes []dbsqlc.TunnelRoute) ([]byte, error) {
	var expiresAt *time.Time
	if tunnel.ExpiresAt.Valid {
		value := tunnel.ExpiresAt.Time.UTC()
		expiresAt = &value
	}
	items := make([]initialTunnelRouteSnapshot, 0, len(routes))
	for _, route := range routes {
		items = append(items, snapshotRoute(route))
	}
	encoded, err := json.Marshal(initialTunnelConfigSnapshot{Schema: Schema, Kind: "tunnel_config_snapshot", TunnelID: tunnel.ID, Generation: tunnel.Generation, Name: tunnel.Name, DesiredState: tunnel.DesiredState,
		AccessMode: tunnel.AccessMode, StableEndpoint: tunnel.StableEndpoint, ExpiresAt: expiresAt, Routes: items})
	if err != nil {
		return nil, err
	}
	return canonicalConfigSnapshot(encoded)
}

type resourceOperationInput struct {
	ID             string
	AccountID      string
	IdempotencyKey string
	RequestHash    [sha256.Size]byte
	OperationType  string
	ResourceKind   string
	ResourceID     string
	CorrelationID  string
}

func beginResourceOperation(ctx context.Context, q *dbsqlc.Queries, input resourceOperationInput) (dbsqlc.Operation, bool, error) {
	op, err := q.CreatePreviewTunnelOperation(ctx, dbsqlc.CreatePreviewTunnelOperationParams{
		ID: input.ID, AccountID: input.AccountID, IdempotencyKey: input.IdempotencyKey, RequestHash: input.RequestHash[:],
		OperationType: input.OperationType, ResourceKind: input.ResourceKind, ResourceID: nullableString(input.ResourceID),
		Phase: "persisting", State: "running", Progress: 20, Outcome: "unchanged", CorrelationID: input.CorrelationID,
	})
	if err == nil {
		return op, false, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return dbsqlc.Operation{}, false, translate(err)
	}
	existing, getErr := q.GetPreviewTunnelOperationByIdempotency(ctx, dbsqlc.GetPreviewTunnelOperationByIdempotencyParams{AccountID: input.AccountID, IdempotencyKey: input.IdempotencyKey})
	if getErr != nil {
		return dbsqlc.Operation{}, false, translate(getErr)
	}
	if existing.OperationType != input.OperationType || existing.ResourceKind != input.ResourceKind || !existing.ResourceID.Valid || existing.ResourceID.String != input.ResourceID || !bytes.Equal(existing.RequestHash, input.RequestHash[:]) {
		return dbsqlc.Operation{}, false, ErrIdempotencyConflict
	}
	return existing, true, nil
}

func completeResourceOperation(ctx context.Context, q *dbsqlc.Queries, operationID, resourceID, phase, outcome string, now time.Time) (dbsqlc.Operation, error) {
	op, err := q.CompletePreviewTunnelOperation(ctx, dbsqlc.CompletePreviewTunnelOperationParams{ResourceID: nullableString(resourceID), Phase: phase,
		State: "succeeded", Progress: 100, Outcome: outcome, ResultReference: nullableString(resourceID), UpdatedAt: now.UTC(),
		CompletedAt: sql.NullTime{Time: now.UTC(), Valid: true}, ID: operationID})
	return op, translate(err)
}

func advanceResourceOperation(ctx context.Context, q *dbsqlc.Queries, operationID, resourceID, phase string, progress int16, now time.Time) (dbsqlc.Operation, error) {
	op, err := q.CompletePreviewTunnelOperation(ctx, dbsqlc.CompletePreviewTunnelOperationParams{ResourceID: nullableString(resourceID), Phase: phase,
		State: "running", Progress: progress, Outcome: "changed", ResultReference: sql.NullString{}, UpdatedAt: now.UTC(), CompletedAt: sql.NullTime{}, ID: operationID})
	return op, translate(err)
}

type resourceAuditInput struct {
	AuditEventID       string
	ParentAuditEventID string
	AccountID          string
	ActorID            string
	ActorType          string
	EventType          string
	ParentEventType    string
	ResourceType       string
	ResourceID         string
	TunnelID           string
	OperationID        string
	IdempotencyKey     string
	RequestID          string
	CorrelationID      string
	SourceDeviceID     string
	Now                time.Time
	Metadata           map[string]any
	Message            string
}

func recordResourceChange(ctx context.Context, q *dbsqlc.Queries, input resourceAuditInput) error {
	if err := insertResourceAudit(ctx, q, input.AuditEventID, input.AccountID, input.ActorID, input.ActorType, input.EventType, "update", "changed", input.ResourceType, input.ResourceID,
		input.IdempotencyKey, input.RequestID, input.CorrelationID, input.SourceDeviceID, input.Now, input.Metadata); err != nil {
		return err
	}
	if input.ParentAuditEventID != "" {
		metadata := map[string]any{"resource_kind": input.ResourceType, "resource_id": input.ResourceID}
		for key, value := range input.Metadata {
			metadata[key] = value
		}
		if err := insertResourceAudit(ctx, q, input.ParentAuditEventID, input.AccountID, input.ActorID, input.ActorType, input.ParentEventType, "update", "changed", "tunnel", input.TunnelID,
			input.IdempotencyKey, input.RequestID, input.CorrelationID, input.SourceDeviceID, input.Now, metadata); err != nil {
			return err
		}
	}
	return insertResourceLog(ctx, q, input)
}

func insertResourceAudit(ctx context.Context, q *dbsqlc.Queries, id, accountID, actorID, actorType, eventType, changeType, outcome, resourceType, resourceID, idempotencyKey, requestID, correlationID, sourceDeviceID string, createdAt time.Time, metadata map[string]any) error {
	safe, err := previewtunnelapi.SafeMetadata(metadata)
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(safe)
	if err != nil {
		return fmt.Errorf("encode resource audit metadata: %w", err)
	}
	_, err = q.InsertPreviewTunnelAuditEvent(ctx, dbsqlc.InsertPreviewTunnelAuditEventParams{
		ID: id, AccountID: nullableString(accountID), ActorID: nullableString(actorID), ActorUserID: actorUserID(actorType, actorID), ActorType: actorType,
		EventType: eventType, ChangeType: changeType, Outcome: outcome, ResourceType: resourceType, ResourceID: resourceID,
		IdempotencyKey: nullableString(idempotencyKey), RequestID: nullableString(requestID), CorrelationID: nullableString(correlationID), SourceDeviceID: nullableString(sourceDeviceID), Metadata: encoded, CreatedAt: createdAt.UTC(),
	})
	return translate(err)
}

func insertResourceLog(ctx context.Context, q *dbsqlc.Queries, input resourceAuditInput) error {
	if err := validateLogText(input.Message, maxResourceLogMessageBytes); err != nil {
		return err
	}
	if err := validateLogCorrelation(input.CorrelationID); err != nil {
		return err
	}
	safe, err := previewtunnelapi.SafeMetadata(input.Metadata)
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(safe)
	if err != nil {
		return err
	}
	code := strings.ReplaceAll(input.EventType, ".", "_")
	_, err = q.CreateTunnelLogEntryV1(ctx, dbsqlc.CreateTunnelLogEntryV1Params{ID: "log_" + input.AuditEventID, AccountID: input.AccountID, TunnelID: nullableString(input.TunnelID),
		Level: "info", Component: "control", Code: code, Message: input.Message, Metadata: encoded, CorrelationID: input.CorrelationID, OccurredAt: input.Now.UTC()})
	return translate(err)
}

func validateRouteRecord(input RouteRecord, requireGeneration bool) error {
	for name, value := range map[string]string{"operation_id": input.OperationID, "audit_event_id": input.AuditEventID, "account_id": input.AccountID, "tunnel_id": input.TunnelID, "route_id": input.RouteID, "idempotency_key": input.IdempotencyKey, "actor_id": input.ActorID, "actor_type": input.ActorType, "correlation_id": input.CorrelationID} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%w: %s is required", ErrInvalidInput, name)
		}
	}
	if requireGeneration && input.ExpectedGeneration < 1 {
		return fmt.Errorf("%w: expected generation is required", ErrInvalidInput)
	}
	if input.RequestHash == ([sha256.Size]byte{}) {
		return fmt.Errorf("%w: request hash is required", ErrInvalidInput)
	}
	if !validActorType(input.ActorType) {
		return fmt.Errorf("%w: actor type is invalid", ErrInvalidInput)
	}
	return nil
}

func (r *SQLRepository) ListResourceDomains(ctx context.Context, accountID, tunnelID string, after *ListPosition, limit int) ([]dbsqlc.TunnelDomain, error) {
	if strings.TrimSpace(accountID) == "" || strings.TrimSpace(tunnelID) == "" || limit < 1 || limit > previewtunnelapi.MaximumPageLimit+1 {
		return nil, ErrInvalidInput
	}
	createdAt, id := resourceAfter(after)
	rows, err := r.db.Queries().ListTunnelDomainsV1(ctx, dbsqlc.ListTunnelDomainsV1Params{AccountID: accountID, TunnelID: tunnelID, AfterCreatedAt: createdAt, AfterID: id, RowLimit: int32(limit)})
	return rows, translate(err)
}

func (r *SQLRepository) GetResourceDomain(ctx context.Context, accountID, tunnelID, domainID string) (dbsqlc.TunnelDomain, error) {
	if strings.TrimSpace(accountID) == "" || strings.TrimSpace(tunnelID) == "" || strings.TrimSpace(domainID) == "" {
		return dbsqlc.TunnelDomain{}, ErrInvalidInput
	}
	row, err := r.db.Queries().GetTunnelDomainV1(ctx, dbsqlc.GetTunnelDomainV1Params{DomainID: domainID, AccountID: accountID, TunnelID: tunnelID})
	if errors.Is(err, pgx.ErrNoRows) {
		return dbsqlc.TunnelDomain{}, ErrDomainNotFound
	}
	return row, translate(err)
}

func (r *SQLRepository) CreateResourceDomain(ctx context.Context, input DomainRecord) (ResourceMutationRecord, error) {
	if err := validateDomainRecord(input, false); err != nil {
		return ResourceMutationRecord{}, err
	}
	var result ResourceMutationRecord
	err := r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := tx.Queries()
		tunnel, err := q.GetTunnelForResourceV1(ctx, dbsqlc.GetTunnelForResourceV1Params{TunnelID: input.TunnelID, AccountID: input.AccountID})
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return translate(err)
		}
		if tunnel.DesiredState == DesiredDeleted {
			return ErrTerminalState
		}
		route, err := q.GetTunnelRouteV1(ctx, dbsqlc.GetTunnelRouteV1Params{RouteID: input.RouteID, TunnelID: input.TunnelID, AccountID: input.AccountID})
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrRouteNotFound
		}
		if err != nil {
			return translate(err)
		}
		if route.DeletedAt.Valid || route.DesiredState == "deleted" {
			return ErrRouteNotFound
		}
		op, replayed, err := beginResourceOperation(ctx, q, resourceOperationInput{ID: input.OperationID, AccountID: input.AccountID, IdempotencyKey: input.IdempotencyKey, RequestHash: input.RequestHash, OperationType: "domain.create", ResourceKind: "domain_binding", ResourceID: input.DomainID, CorrelationID: input.CorrelationID})
		if err != nil {
			return err
		}
		if replayed {
			result.Operation = op
			result.Replayed = true
			if op.ResourceID.Valid {
				result.Domain, err = q.GetTunnelDomainV1(ctx, dbsqlc.GetTunnelDomainV1Params{DomainID: op.ResourceID.String, AccountID: input.AccountID, TunnelID: input.TunnelID})
				if errors.Is(err, pgx.ErrNoRows) {
					return ErrDomainNotFound
				}
				return translate(err)
			}
			return nil
		}
		if existing, lookupErr := q.GetTunnelDomainByHostnameV1(ctx, input.Hostname); lookupErr == nil {
			if domainClaimBlocked(existing, input.Now) {
				return ErrDomainConflict
			}
		} else if !errors.Is(lookupErr, pgx.ErrNoRows) {
			return translate(lookupErr)
		}
		if input.DNSTarget == "" {
			parsed, parseErr := url.Parse(tunnel.StableEndpoint)
			if parseErr != nil || parsed.Hostname() == "" {
				return fmt.Errorf("%w: stable endpoint target is invalid", ErrInvalidInput)
			}
			input.DNSTarget = strings.ToLower(parsed.Hostname())
		}
		if input.DNSProvider == "" {
			input.DNSProvider = "generic"
		}
		if input.CertificateStrategy == "" {
			input.CertificateStrategy = "managed"
		}
		if _, err := normalizeDomainCertificateStrategy(input.CertificateStrategy, input.MatchType); err != nil {
			return err
		}
		if len(input.ExpectedRecords) == 0 {
			recordType, _ := dnsRecordTypeAndNote(input.Hostname, input.DNSProvider)
			input.ExpectedRecords, err = json.Marshal([]DNSRecordInstruction{{Name: input.Hostname, Type: recordType, Value: input.DNSTarget, TTL: 300}})
			if err != nil {
				return err
			}
		}
		domain, err := q.CreateTunnelDomainV1(ctx, dbsqlc.CreateTunnelDomainV1Params{ID: input.DomainID, AccountID: input.AccountID, TunnelID: input.TunnelID, RouteID: input.RouteID,
			Hostname: input.Hostname, MatchType: input.MatchType, OwnershipChallengeReference: input.ChallengeReference, DnsTarget: input.DNSTarget,
			ObservedRecords: []byte("[]"), CertificateStrategy: input.CertificateStrategy, DnsProvider: input.DNSProvider, ExpectedRecords: input.ExpectedRecords, Now: input.Now})
		if err != nil {
			return translate(err)
		}
		op, err = advanceResourceOperation(ctx, q, op.ID, domain.ID, "waiting_for_dns", 35, input.Now)
		if err != nil {
			return err
		}
		if err := recordResourceChange(ctx, q, resourceAuditInput{AuditEventID: input.AuditEventID, ParentAuditEventID: input.ParentAuditEventID, AccountID: input.AccountID,
			ActorID: auditActorID(input.ActorID, input.AuditActorID), ActorType: input.ActorType, EventType: "domain.created", ParentEventType: "tunnel.domain_created",
			ResourceType: "domain_binding", ResourceID: domain.ID, TunnelID: input.TunnelID, OperationID: op.ID, IdempotencyKey: input.IdempotencyKey,
			RequestID: input.RequestID, CorrelationID: input.CorrelationID, SourceDeviceID: input.SourceDeviceID, Now: input.Now,
			Metadata: map[string]any{"hostname": input.Hostname, "state": "waiting_dns"}, Message: "domain binding persisted; DNS ownership proof pending"}); err != nil {
			return err
		}
		result = ResourceMutationRecord{Domain: domain, Operation: op, Changed: true}
		return nil
	})
	return result, translate(err)
}

func domainClaimBlocked(existing dbsqlc.TunnelDomain, now time.Time) bool {
	return !existing.DeletedAt.Valid || (existing.QuarantineUntil.Valid && existing.QuarantineUntil.Time.After(now))
}

func (r *SQLRepository) DeleteResourceDomain(ctx context.Context, input DomainRecord) (ResourceMutationRecord, error) {
	if err := validateDomainRecord(input, true); err != nil {
		return ResourceMutationRecord{}, err
	}
	var result ResourceMutationRecord
	err := r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := tx.Queries()
		tunnel, err := q.GetTunnelForResourceV1(ctx, dbsqlc.GetTunnelForResourceV1Params{TunnelID: input.TunnelID, AccountID: input.AccountID})
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return translate(err)
		}
		if tunnel.DesiredState == DesiredDeleted {
			return ErrTerminalState
		}
		op, replayed, err := beginResourceOperation(ctx, q, resourceOperationInput{ID: input.OperationID, AccountID: input.AccountID, IdempotencyKey: input.IdempotencyKey, RequestHash: input.RequestHash, OperationType: "domain.delete", ResourceKind: "domain_binding", ResourceID: input.DomainID, CorrelationID: input.CorrelationID})
		if err != nil {
			return err
		}
		current, err := q.GetTunnelDomainV1(ctx, dbsqlc.GetTunnelDomainV1Params{DomainID: input.DomainID, AccountID: input.AccountID, TunnelID: input.TunnelID})
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrDomainNotFound
		}
		if err != nil {
			return translate(err)
		}
		if replayed {
			result = ResourceMutationRecord{Domain: current, Operation: op, Replayed: true, Changed: op.Outcome == "changed"}
			return nil
		}
		if current.DeletedAt.Valid {
			op, err = completeResourceOperation(ctx, q, op.ID, current.ID, "ready", "unchanged", input.Now)
			if err != nil {
				return err
			}
			result = ResourceMutationRecord{Domain: current, Operation: op}
			return nil
		}
		if current.Generation != input.ExpectedGeneration {
			return ErrGenerationConflict
		}
		current, err = q.DeleteTunnelDomainV1(ctx, dbsqlc.DeleteTunnelDomainV1Params{Now: sql.NullTime{Time: input.Now, Valid: true}, QuarantineUntil: sql.NullTime{Time: input.Now.Add(7 * 24 * time.Hour), Valid: true}, DomainID: input.DomainID, AccountID: input.AccountID, TunnelID: input.TunnelID, ExpectedGeneration: input.ExpectedGeneration})
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrGenerationConflict
		}
		if err != nil {
			return translate(err)
		}
		op, err = completeResourceOperation(ctx, q, op.ID, current.ID, "ready", "changed", input.Now)
		if err != nil {
			return err
		}
		if err := recordResourceChange(ctx, q, resourceAuditInput{AuditEventID: input.AuditEventID, ParentAuditEventID: input.ParentAuditEventID, AccountID: input.AccountID,
			ActorID: auditActorID(input.ActorID, input.AuditActorID), ActorType: input.ActorType, EventType: "domain.deleted", ParentEventType: "tunnel.domain_deleted",
			ResourceType: "domain_binding", ResourceID: current.ID, TunnelID: input.TunnelID, OperationID: op.ID, IdempotencyKey: input.IdempotencyKey,
			RequestID: input.RequestID, CorrelationID: input.CorrelationID, SourceDeviceID: input.SourceDeviceID, Now: input.Now,
			Metadata: map[string]any{"state": "quarantined"}, Message: "domain binding revoked; DNS and certificate cleanup deferred"}); err != nil {
			return err
		}
		result = ResourceMutationRecord{Domain: current, Operation: op, Changed: true}
		return nil
	})
	return result, translate(err)
}

func (r *SQLRepository) BeginResourceDomainVerification(ctx context.Context, input DomainRecord) (ResourceMutationRecord, error) {
	if err := validateDomainRecord(input, true); err != nil {
		return ResourceMutationRecord{}, err
	}
	var result ResourceMutationRecord
	err := r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := tx.Queries()
		tunnel, err := q.GetTunnelForResourceV1(ctx, dbsqlc.GetTunnelForResourceV1Params{TunnelID: input.TunnelID, AccountID: input.AccountID})
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return translate(err)
		}
		if tunnel.DesiredState == DesiredDeleted {
			return ErrTerminalState
		}
		op, replayed, err := beginResourceOperation(ctx, q, resourceOperationInput{ID: input.OperationID, AccountID: input.AccountID, IdempotencyKey: input.IdempotencyKey, RequestHash: input.RequestHash, OperationType: "domain.verify", ResourceKind: "domain_binding", ResourceID: input.DomainID, CorrelationID: input.CorrelationID})
		if err != nil {
			return err
		}
		current, err := q.GetTunnelDomainV1(ctx, dbsqlc.GetTunnelDomainV1Params{DomainID: input.DomainID, AccountID: input.AccountID, TunnelID: input.TunnelID})
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrDomainNotFound
		}
		if err != nil {
			return translate(err)
		}
		if replayed {
			result = ResourceMutationRecord{Domain: current, Operation: op, Replayed: true, Changed: op.Outcome == "changed"}
			return nil
		}
		if current.DeletedAt.Valid {
			return ErrTerminalState
		}
		if current.Generation != input.ExpectedGeneration {
			return ErrGenerationConflict
		}
		current, err = q.BeginTunnelDomainVerificationV1(ctx, dbsqlc.BeginTunnelDomainVerificationV1Params{Now: input.Now, DomainID: input.DomainID, AccountID: input.AccountID, TunnelID: input.TunnelID, ExpectedGeneration: input.ExpectedGeneration})
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrGenerationConflict
		}
		if err != nil {
			return translate(err)
		}
		// Verification is intentionally not marked successful here. TRK-18 owns
		// external DNS observation and will perform the proof-bearing transition.
		op, err = advanceResourceOperation(ctx, q, op.ID, current.ID, "waiting_for_dns", 40, input.Now)
		if err != nil {
			return err
		}
		if err := recordResourceChange(ctx, q, resourceAuditInput{AuditEventID: input.AuditEventID, ParentAuditEventID: input.ParentAuditEventID, AccountID: input.AccountID,
			ActorID: auditActorID(input.ActorID, input.AuditActorID), ActorType: input.ActorType, EventType: "domain.verification_requested", ParentEventType: "tunnel.domain_verification_requested",
			ResourceType: "domain_binding", ResourceID: current.ID, TunnelID: input.TunnelID, OperationID: op.ID, IdempotencyKey: input.IdempotencyKey,
			RequestID: input.RequestID, CorrelationID: input.CorrelationID, SourceDeviceID: input.SourceDeviceID, Now: input.Now,
			Metadata: map[string]any{"state": "waiting_dns"}, Message: "DNS verification requested; no external proof observed yet"}); err != nil {
			return err
		}
		result = ResourceMutationRecord{Domain: current, Operation: op, Changed: true}
		return nil
	})
	return result, translate(err)
}

func validateDomainRecord(input DomainRecord, requireGeneration bool) error {
	for name, value := range map[string]string{"operation_id": input.OperationID, "audit_event_id": input.AuditEventID, "account_id": input.AccountID, "tunnel_id": input.TunnelID, "domain_id": input.DomainID, "route_id": input.RouteID, "hostname": input.Hostname, "idempotency_key": input.IdempotencyKey, "actor_id": input.ActorID, "actor_type": input.ActorType, "correlation_id": input.CorrelationID} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%w: %s is required", ErrInvalidInput, name)
		}
	}
	if requireGeneration && input.ExpectedGeneration < 1 {
		return fmt.Errorf("%w: expected generation is required", ErrInvalidInput)
	}
	if input.RequestHash == ([sha256.Size]byte{}) {
		return fmt.Errorf("%w: request hash is required", ErrInvalidInput)
	}
	if !validActorType(input.ActorType) {
		return fmt.Errorf("%w: actor type is invalid", ErrInvalidInput)
	}
	return nil
}

func (r *SQLRepository) ListResourceConnectors(ctx context.Context, accountID, tunnelID string, after *ListPosition, limit int) ([]dbsqlc.TunnelConnector, error) {
	if strings.TrimSpace(accountID) == "" || strings.TrimSpace(tunnelID) == "" || limit < 1 || limit > previewtunnelapi.MaximumPageLimit+1 {
		return nil, ErrInvalidInput
	}
	createdAt, id := resourceAfter(after)
	rows, err := r.db.Queries().ListTunnelConnectorsV1(ctx, dbsqlc.ListTunnelConnectorsV1Params{AccountID: accountID, TunnelID: tunnelID, AfterCreatedAt: createdAt, AfterID: id, RowLimit: int32(limit)})
	return rows, translate(err)
}

func (r *SQLRepository) GetResourceConnector(ctx context.Context, accountID, tunnelID, connectorID string) (dbsqlc.TunnelConnector, error) {
	if strings.TrimSpace(accountID) == "" || strings.TrimSpace(tunnelID) == "" || strings.TrimSpace(connectorID) == "" {
		return dbsqlc.TunnelConnector{}, ErrInvalidInput
	}
	row, err := r.db.Queries().GetTunnelConnectorV1(ctx, dbsqlc.GetTunnelConnectorV1Params{ConnectorID: connectorID, TunnelID: tunnelID, AccountID: accountID})
	if errors.Is(err, pgx.ErrNoRows) {
		return dbsqlc.TunnelConnector{}, ErrConnectorNotFound
	}
	return row, translate(err)
}

func (r *SQLRepository) IssueConnectorEnrollment(ctx context.Context, input EnrollmentRecordInput) (EnrollmentRecord, error) {
	if err := validateEnrollmentRecordInput(input); err != nil {
		return EnrollmentRecord{}, err
	}
	var result EnrollmentRecord
	err := r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := tx.Queries()
		tunnel, err := q.GetTunnelForResourceV1(ctx, dbsqlc.GetTunnelForResourceV1Params{TunnelID: input.TunnelID, AccountID: input.AccountID})
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return translate(err)
		}
		if tunnel.DesiredState == DesiredDeleted {
			return ErrTerminalState
		}
		if err := verifyHostWithQueries(ctx, q, input.AccountID, input.HostID); err != nil {
			return err
		}
		op, replayed, err := beginResourceOperation(ctx, q, resourceOperationInput{ID: input.OperationID, AccountID: input.AccountID, IdempotencyKey: input.IdempotencyKey, RequestHash: input.RequestHash, OperationType: "connector.enrollment.issue", ResourceKind: "connector", ResourceID: input.EnrollmentID, CorrelationID: input.CorrelationID})
		if err != nil {
			return err
		}
		if replayed {
			enrollment, getErr := q.GetTunnelConnectorEnrollmentByOperationV1(ctx, dbsqlc.GetTunnelConnectorEnrollmentByOperationV1Params{OperationID: op.ID, AccountID: input.AccountID})
			if getErr != nil {
				if errors.Is(getErr, pgx.ErrNoRows) {
					return ErrEnrollmentAlreadyIssued
				}
				return translate(getErr)
			}
			// Enrollment tokens are intentionally write-only and are never
			// persisted. A lost response therefore cannot be replayed safely.
			// Make that recovery boundary explicit instead of returning a
			// successful response with an empty token.
			_ = enrollment
			return ErrEnrollmentAlreadyIssued
		}
		enrollment, err := q.CreateTunnelConnectorEnrollmentV1(ctx, dbsqlc.CreateTunnelConnectorEnrollmentV1Params{ID: input.EnrollmentID, AccountID: input.AccountID, TunnelID: input.TunnelID, HostID: input.HostID, OperationID: op.ID, TokenHash: input.TokenHash, Capabilities: input.Capabilities, ExpiresAt: input.ExpiresAt, CreatedByActorID: input.ActorID, Now: input.Now})
		if err != nil {
			return translate(err)
		}
		op, err = completeResourceOperation(ctx, q, op.ID, enrollment.ID, "ready", "changed", input.Now)
		if err != nil {
			return err
		}
		if err := recordResourceChange(ctx, q, resourceAuditInput{AuditEventID: input.AuditEventID, ParentAuditEventID: input.ParentAuditEventID, AccountID: input.AccountID,
			ActorID: auditActorID(input.ActorID, input.AuditActorID), ActorType: input.ActorType, EventType: "connector.enrollment_issued", ParentEventType: "tunnel.connector_enrollment_issued",
			ResourceType: "connector", ResourceID: enrollment.ID, TunnelID: input.TunnelID, OperationID: op.ID, IdempotencyKey: input.IdempotencyKey, RequestID: input.RequestID,
			CorrelationID: input.CorrelationID, SourceDeviceID: input.SourceDeviceID, Now: input.Now,
			Metadata: map[string]any{"host_id": input.HostID, "expires_at": input.ExpiresAt.UTC().Format(time.RFC3339Nano)}, Message: "single-use connector enrollment issued"}); err != nil {
			return err
		}
		result = EnrollmentRecord{Enrollment: enrollment, Operation: op, Token: input.Token}
		return nil
	})
	return result, translate(err)
}

func (r *SQLRepository) ExchangeConnectorEnrollment(ctx context.Context, input EnrollmentExchangeRecord) (ResourceMutationRecord, error) {
	if err := validateExchangeRecord(input); err != nil {
		return ResourceMutationRecord{}, err
	}
	var result ResourceMutationRecord
	err := r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := tx.Queries()
		enrollment, err := q.GetTunnelConnectorEnrollmentByTokenV1(ctx, input.TokenHash)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrEnrollmentExpired
		}
		if err != nil {
			return translate(err)
		}
		if enrollment.AccountID != input.AccountID || enrollment.HostID != input.HostID || (input.TunnelID != "" && enrollment.TunnelID != input.TunnelID) {
			return ErrEnrollmentExpired
		}
		tunnel, err := q.GetTunnelForResourceV1(ctx, dbsqlc.GetTunnelForResourceV1Params{TunnelID: enrollment.TunnelID, AccountID: enrollment.AccountID})
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return translate(err)
		}
		if err := validateStableEndpointForID(tunnel.StableEndpoint, tunnel.StableEndpointID); err != nil {
			return fmt.Errorf("%w: tunnel managed endpoint is invalid", ErrInvalidInput)
		}
		if tunnel.DesiredState == DesiredDeleted {
			return ErrTerminalState
		}
		op, replayed, err := beginResourceOperation(ctx, q, resourceOperationInput{ID: input.OperationID, AccountID: input.AccountID, IdempotencyKey: input.IdempotencyKey, RequestHash: input.RequestHash, OperationType: "connector.enrollment.exchange", ResourceKind: "connector", ResourceID: input.ConnectorID, CorrelationID: input.CorrelationID})
		if err != nil {
			return err
		}
		if replayed {
			if !op.ResourceID.Valid {
				return ErrOperationInProgress
			}
			connector, getErr := q.GetTunnelConnectorV1(ctx, dbsqlc.GetTunnelConnectorV1Params{ConnectorID: op.ResourceID.String, TunnelID: enrollment.TunnelID, AccountID: enrollment.AccountID})
			if errors.Is(getErr, pgx.ErrNoRows) {
				return ErrConnectorNotFound
			}
			if getErr != nil {
				return translate(getErr)
			}
			processGeneration, reserveErr := reserveConnectorActivation(ctx, tx, enrollment.AccountID, enrollment.TunnelID, connector.ID, connector.HostID, op.ID, connector.RotationGeneration, input.Now)
			if reserveErr != nil {
				return reserveErr
			}
			result = ResourceMutationRecord{Connector: connector, Operation: op, StableEndpointID: tunnel.StableEndpointID, ProcessGeneration: processGeneration, Replayed: true, Changed: op.Outcome == "changed"}
			return nil
		}
		if !enrollment.ExpiresAt.After(input.Now) {
			return ErrEnrollmentExpired
		}
		if enrollment.ConsumedAt.Valid {
			return ErrEnrollmentReplay
		}
		connector, getErr := q.GetTunnelConnectorByHostForUpdateV1(ctx, dbsqlc.GetTunnelConnectorByHostForUpdateV1Params{TunnelID: enrollment.TunnelID, HostID: enrollment.HostID})
		hasConnector := getErr == nil
		if getErr != nil && !errors.Is(getErr, pgx.ErrNoRows) {
			return translate(getErr)
		}
		if hasConnector && connector.DesiredState != "revoked" {
			return ErrConnectorConflict
		}
		if hasConnector {
			connector, err = q.ReactivateTunnelConnectorV1(ctx, dbsqlc.ReactivateTunnelConnectorV1Params{CredentialReference: input.CredentialReference, CredentialThumbprint: input.CredentialThumbprint, ConnectorID: connector.ID, TunnelID: enrollment.TunnelID, Now: input.Now})
		} else {
			connector, err = q.CreateTunnelConnectorV1(ctx, dbsqlc.CreateTunnelConnectorV1Params{ID: input.ConnectorID, TunnelID: enrollment.TunnelID, HostID: enrollment.HostID, CredentialReference: input.CredentialReference,
				CredentialThumbprint: input.CredentialThumbprint, SoftwareVersion: input.SoftwareVersion, ProtocolVersion: input.ProtocolVersion, OperatingSystem: input.OperatingSystem, Architecture: input.Architecture, Now: input.Now})
		}
		if err != nil {
			return translate(err)
		}
		if hasConnector {
			if _, err := q.MarkTunnelConnectorCredentialOverlapV1(ctx, dbsqlc.MarkTunnelConnectorCredentialOverlapV1Params{ValidUntil: input.Now.Add(input.CredentialOverlap), ConnectorID: connector.ID, Generation: connector.RotationGeneration}); err != nil {
				return translate(err)
			}
		}
		_, generationErr := q.CreateTunnelConnectorCredentialGenerationV1(ctx, dbsqlc.CreateTunnelConnectorCredentialGenerationV1Params{ID: input.CredentialGenerationID, ConnectorID: connector.ID, TunnelID: enrollment.TunnelID,
			Generation: connector.RotationGeneration, CredentialReference: input.CredentialReference, CredentialThumbprint: input.CredentialThumbprint,
			VerifierAlgorithm: input.CredentialVerifierAlgorithm, VerifierPublicKey: input.CredentialVerifierPublicKey,
			State: "active", ValidUntil: input.Now.Add(input.CredentialLifetime), Now: input.Now})
		if generationErr != nil {
			return translate(generationErr)
		}
		// Bind the credential generation to the exact enrollment exchange
		// operation. Connector readiness later uses the authenticated session's
		// credential generation, so concurrent exchanges cannot complete the
		// newest unrelated operation for this connector.
		bindingResult, err := tx.Exec(ctx, `
UPDATE tunnel_connector_credential_generations
SET source_operation_id = $1
			WHERE id = $2 AND connector_id = $3 AND tunnel_id = $4 AND generation = $5`, input.OperationID, input.CredentialGenerationID, connector.ID, enrollment.TunnelID, int64(connector.RotationGeneration))
		if err != nil {
			return err
		}
		if bindingResult.RowsAffected() != 1 {
			return fmt.Errorf("%w: credential generation operation binding was not persisted", ErrGenerationConflict)
		}
		processGeneration, err := reserveConnectorActivation(ctx, tx, enrollment.AccountID, enrollment.TunnelID, connector.ID, connector.HostID, op.ID, connector.RotationGeneration, input.Now)
		if err != nil {
			return err
		}
		if _, err := q.MarkTunnelConnectorEnrollmentConsumedV1(ctx, dbsqlc.MarkTunnelConnectorEnrollmentConsumedV1Params{ConsumedAt: sql.NullTime{Time: input.Now, Valid: true}, ConnectorID: nullableString(connector.ID), ID: enrollment.ID}); err != nil {
			return translate(err)
		}
		op, err = advanceResourceOperation(ctx, q, op.ID, connector.ID, "connecting", 60, input.Now)
		if err != nil {
			return err
		}
		if err := recordResourceChange(ctx, q, resourceAuditInput{AuditEventID: input.AuditEventID, ParentAuditEventID: input.ParentAuditEventID, AccountID: input.AccountID,
			ActorID: auditActorID(input.ActorID, input.AuditActorID), ActorType: input.ActorType, EventType: "connector.enrolled", ParentEventType: "tunnel.connector_enrolled",
			ResourceType: "connector", ResourceID: connector.ID, TunnelID: enrollment.TunnelID, OperationID: op.ID, IdempotencyKey: input.IdempotencyKey, RequestID: input.RequestID,
			CorrelationID: input.CorrelationID, SourceDeviceID: input.SourceDeviceID, Now: input.Now,
			Metadata: map[string]any{"host_id": enrollment.HostID, "rotation_generation": connector.RotationGeneration}, Message: "connector identity enrolled"}); err != nil {
			return err
		}
		result = ResourceMutationRecord{Connector: connector, Operation: op, StableEndpointID: tunnel.StableEndpointID, ProcessGeneration: processGeneration, Changed: true}
		return nil
	})
	return result, translate(err)
}

func reserveConnectorActivation(ctx context.Context, tx *db.Tx, accountID, tunnelID, connectorID, hostID, operationID string, credentialGeneration int64, now time.Time) (int64, error) {
	if ctx == nil || tx == nil || accountID == "" || tunnelID == "" || connectorID == "" || hostID == "" || operationID == "" || credentialGeneration < 1 || now.IsZero() {
		return 0, ErrInvalidInput
	}
	var lockedID string
	if err := tx.QueryRow(ctx, `
SELECT c.id
FROM tunnel_connectors AS c
JOIN tunnels AS t ON t.id = c.tunnel_id
WHERE c.id = $1 AND c.tunnel_id = $2 AND c.host_id = $3
  AND t.account_id = $4 AND t.deleted_at IS NULL
FOR UPDATE OF c`, connectorID, tunnelID, hostID, accountID).Scan(&lockedID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, ErrConnectorNotFound
		}
		return 0, err
	}
	var storedAccountID, storedTunnelID, storedConnectorID, storedHostID string
	var storedCredentialGeneration, storedProcessGeneration int64
	err := tx.QueryRow(ctx, `
SELECT account_id, tunnel_id, connector_id, host_id,
       credential_generation, process_generation
FROM tunnel_connector_activations
WHERE operation_id = $1`, operationID).Scan(
		&storedAccountID, &storedTunnelID, &storedConnectorID, &storedHostID,
		&storedCredentialGeneration, &storedProcessGeneration,
	)
	if err == nil {
		if storedAccountID != accountID || storedTunnelID != tunnelID || storedConnectorID != connectorID || storedHostID != hostID || storedCredentialGeneration != credentialGeneration || storedProcessGeneration < 1 {
			return 0, ErrGenerationConflict
		}
		return storedProcessGeneration, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return 0, err
	}
	var highest int64
	if err = tx.QueryRow(ctx, `
SELECT GREATEST(
  COALESCE((SELECT MAX(process_generation) FROM tunnel_connector_sessions WHERE connector_id = $1), 0),
  COALESCE((SELECT MAX(process_generation) FROM tunnel_connector_activations WHERE connector_id = $1), 0)
)`, connectorID).Scan(&highest); err != nil {
		return 0, err
	}
	if highest < 0 || highest == int64(^uint64(0)>>1) {
		return 0, ErrGenerationConflict
	}
	processGeneration := highest + 1
	if err = tx.QueryRow(ctx, `
INSERT INTO tunnel_connector_activations
  (operation_id, account_id, tunnel_id, connector_id, host_id,
   credential_generation, process_generation, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING process_generation`, operationID, accountID, tunnelID, connectorID, hostID, credentialGeneration, processGeneration, now).Scan(&storedProcessGeneration); err != nil {
		return 0, translate(err)
	}
	if storedProcessGeneration != processGeneration {
		return 0, ErrGenerationConflict
	}
	return processGeneration, nil
}

func validateEnrollmentRecordInput(input EnrollmentRecordInput) error {
	for name, value := range map[string]string{"operation_id": input.OperationID, "enrollment_id": input.EnrollmentID, "account_id": input.AccountID, "tunnel_id": input.TunnelID, "host_id": input.HostID, "actor_id": input.ActorID, "actor_type": input.ActorType, "correlation_id": input.CorrelationID, "idempotency_key": input.IdempotencyKey} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%w: %s is required", ErrInvalidInput, name)
		}
	}
	if len(input.TokenHash) != sha256.Size || input.RequestHash == ([sha256.Size]byte{}) || !validActorType(input.ActorType) || !input.ExpiresAt.After(input.Now) || input.CredentialLifetime <= 0 {
		return fmt.Errorf("%w: invalid enrollment bounds", ErrInvalidInput)
	}
	return nil
}

func validateExchangeRecord(input EnrollmentExchangeRecord) error {
	for name, value := range map[string]string{"operation_id": input.OperationID, "audit_event_id": input.AuditEventID, "account_id": input.AccountID, "tunnel_id": input.TunnelID, "host_id": input.HostID, "connector_id": input.ConnectorID, "credential_reference": input.CredentialReference, "credential_thumbprint": input.CredentialThumbprint, "credential_generation_id": input.CredentialGenerationID, "protocol_version": input.ProtocolVersion, "actor_id": input.ActorID, "actor_type": input.ActorType, "correlation_id": input.CorrelationID, "idempotency_key": input.IdempotencyKey} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%w: %s is required", ErrInvalidInput, name)
		}
	}
	if len(input.TokenHash) != sha256.Size || input.RequestHash == ([sha256.Size]byte{}) || !validActorType(input.ActorType) || input.CredentialLifetime <= 0 || input.CredentialOverlap <= 0 ||
		!validateConnectorCredentialVerifier(input.CredentialVerifierAlgorithm, input.CredentialVerifierPublicKey, input.CredentialProof, input.CredentialThumbprint) {
		return fmt.Errorf("%w: invalid enrollment exchange", ErrInvalidInput)
	}
	return nil
}

func (r *SQLRepository) DrainResourceConnector(ctx context.Context, input ConnectorRecord) (ResourceMutationRecord, error) {
	return r.mutateConnector(ctx, input, false)
}

func (r *SQLRepository) RevokeResourceConnector(ctx context.Context, input ConnectorRecord) (ResourceMutationRecord, error) {
	return r.mutateConnector(ctx, input, true)
}

func (r *SQLRepository) mutateConnector(ctx context.Context, input ConnectorRecord, revoke bool) (ResourceMutationRecord, error) {
	if err := validateConnectorRecord(input); err != nil {
		return ResourceMutationRecord{}, err
	}
	operationType := "connector.drain"
	eventType := "connector.draining"
	parentEventType := "tunnel.connector_draining"
	if revoke {
		operationType = "connector.revoke"
		eventType = "connector.revoked"
		parentEventType = "tunnel.connector_revoked"
	}
	var result ResourceMutationRecord
	err := r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := tx.Queries()
		tunnel, err := q.GetTunnelForResourceV1(ctx, dbsqlc.GetTunnelForResourceV1Params{TunnelID: input.TunnelID, AccountID: input.AccountID})
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return translate(err)
		}
		if tunnel.DesiredState == DesiredDeleted {
			return ErrTerminalState
		}
		op, replayed, err := beginResourceOperation(ctx, q, resourceOperationInput{ID: input.OperationID, AccountID: input.AccountID, IdempotencyKey: input.IdempotencyKey, RequestHash: input.RequestHash, OperationType: operationType, ResourceKind: "connector", ResourceID: input.ConnectorID, CorrelationID: input.CorrelationID})
		if err != nil {
			return err
		}
		connector, err := q.GetTunnelConnectorV1(ctx, dbsqlc.GetTunnelConnectorV1Params{ConnectorID: input.ConnectorID, TunnelID: input.TunnelID, AccountID: input.AccountID})
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrConnectorNotFound
		}
		if err != nil {
			return translate(err)
		}
		if replayed {
			result = ResourceMutationRecord{Connector: connector, Operation: op, Replayed: true, Changed: op.Outcome == "changed"}
			return nil
		}
		if revoke && connector.DesiredState == "revoked" {
			op, err = completeResourceOperation(ctx, q, op.ID, connector.ID, "ready", "unchanged", input.Now)
			if err != nil {
				return err
			}
			result = ResourceMutationRecord{Connector: connector, Operation: op}
			return nil
		}
		if !revoke && connector.DesiredState == "revoked" {
			return ErrConnectorConflict
		}
		if connector.Generation != input.ExpectedGeneration {
			return ErrGenerationConflict
		}
		if revoke {
			connector, err = q.RevokeTunnelConnectorV1(ctx, dbsqlc.RevokeTunnelConnectorV1Params{Now: sql.NullTime{Time: input.Now, Valid: true}, ConnectorID: input.ConnectorID, TunnelID: input.TunnelID, ExpectedGeneration: input.ExpectedGeneration})
		} else {
			connector, err = q.DrainTunnelConnectorV1(ctx, dbsqlc.DrainTunnelConnectorV1Params{Now: input.Now, ConnectorID: input.ConnectorID, TunnelID: input.TunnelID, ExpectedGeneration: input.ExpectedGeneration})
		}
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrGenerationConflict
		}
		if err != nil {
			return translate(err)
		}
		phase := "draining"
		if revoke {
			phase = "draining"
		}
		op, err = advanceResourceOperation(ctx, q, op.ID, connector.ID, phase, 60, input.Now)
		if err != nil {
			return err
		}
		if err := recordResourceChange(ctx, q, resourceAuditInput{AuditEventID: input.AuditEventID, ParentAuditEventID: input.ParentAuditEventID, AccountID: input.AccountID,
			ActorID: auditActorID(input.ActorID, input.AuditActorID), ActorType: input.ActorType, EventType: eventType, ParentEventType: parentEventType,
			ResourceType: "connector", ResourceID: connector.ID, TunnelID: input.TunnelID, OperationID: op.ID, IdempotencyKey: input.IdempotencyKey, RequestID: input.RequestID,
			CorrelationID: input.CorrelationID, SourceDeviceID: input.SourceDeviceID, Now: input.Now,
			Metadata: map[string]any{"desired_state": connector.DesiredState, "drain_state": connector.DrainState}, Message: "connector state persisted; session drain pending"}); err != nil {
			return err
		}
		result = ResourceMutationRecord{Connector: connector, Operation: op, Changed: true}
		return nil
	})
	return result, translate(err)
}

func validateConnectorRecord(input ConnectorRecord) error {
	for name, value := range map[string]string{"operation_id": input.OperationID, "audit_event_id": input.AuditEventID, "account_id": input.AccountID, "tunnel_id": input.TunnelID, "connector_id": input.ConnectorID, "idempotency_key": input.IdempotencyKey, "actor_id": input.ActorID, "actor_type": input.ActorType, "correlation_id": input.CorrelationID} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%w: %s is required", ErrInvalidInput, name)
		}
	}
	if input.ExpectedGeneration < 1 || input.RequestHash == ([sha256.Size]byte{}) || !validActorType(input.ActorType) {
		return fmt.Errorf("%w: invalid connector mutation", ErrInvalidInput)
	}
	return nil
}

func (r *SQLRepository) RotateResourceCredentials(ctx context.Context, input RotationRecord) (dbsqlc.Operation, error) {
	if err := validateRotationRecord(input); err != nil {
		return dbsqlc.Operation{}, err
	}
	var result dbsqlc.Operation
	err := r.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		q := tx.Queries()
		tunnel, err := q.GetTunnelForResourceV1(ctx, dbsqlc.GetTunnelForResourceV1Params{TunnelID: input.TunnelID, AccountID: input.AccountID})
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return translate(err)
		}
		// Rotation is an aggregate tunnel operation: every active connector in
		// the tunnel must prove and install the next credential generation before
		// this operation can complete. Keep the operation resource identity on
		// the tunnel so TRK-08 can correlate all targeted connector work without
		// pretending the tunnel ID is a connector ID.
		op, replayed, err := beginResourceOperation(ctx, q, resourceOperationInput{ID: input.OperationID, AccountID: input.AccountID, IdempotencyKey: input.IdempotencyKey, RequestHash: input.RequestHash, OperationType: "connector.credentials.rotate", ResourceKind: "tunnel", ResourceID: input.TunnelID, CorrelationID: input.CorrelationID})
		if err != nil {
			return err
		}
		if replayed {
			result = op
			return nil
		}
		if tunnel.DesiredState == DesiredDeleted {
			return ErrTerminalState
		}
		if tunnel.Generation != input.ExpectedGeneration {
			return ErrGenerationConflict
		}
		connectors, err := q.ListActiveTunnelConnectorsForUpdateV1(ctx, input.TunnelID)
		if err != nil {
			return translate(err)
		}
		rotationTargets := make([]connectorprotocol.RotationTarget, 0, len(connectors))
		rotationTargetSetHash := ""
		for _, connector := range connectors {
			if connector.RotationGeneration <= 0 || connector.RotationGeneration == int64(^uint64(0)>>1) {
				return fmt.Errorf("%w: connector rotation generation is invalid", ErrInvalidInput)
			}
			rotationTargets = append(rotationTargets, connectorprotocol.RotationTarget{
				ConnectorID: connector.ID, HostID: connector.HostID,
				OldCredentialGeneration: uint64(connector.RotationGeneration),
				NewCredentialGeneration: uint64(connector.RotationGeneration) + 1,
			})
		}
		if len(rotationTargets) > 0 {
			plan, err := connectorprotocol.NewRotationPlan(input.AccountID, input.TunnelID, op.ID, rotationTargets)
			if err != nil {
				return err
			}
			rotationTargetSetHash = plan.TargetSetHash
			// Capture the immutable target set in the same serializable
			// transaction as the API operation. A later reconnect or retry must
			// load this set, never recapture whichever connectors happen to be
			// active at that time.
			for _, target := range plan.Targets {
				if _, err := tx.Exec(ctx, `
INSERT INTO tunnel_connector_rotation_targets
  (operation_id, account_id, tunnel_id, connector_id, host_id, target_set_hash,
   old_credential_generation, new_credential_generation, overlap_until,
   new_credential_valid_until, state, created_at, updated_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'pending',$11,$11)
ON CONFLICT (operation_id, connector_id) DO NOTHING`, plan.OperationID, plan.AccountID, plan.TunnelID, target.ConnectorID, target.HostID, plan.TargetSetHash,
					int64(target.OldCredentialGeneration), int64(target.NewCredentialGeneration), input.OverlapUntil, input.Now.Add(input.CredentialLifetime), input.Now); err != nil {
					return translate(err)
				}
			}
			var capturedCount int
			var capturedHash string
			if err := tx.QueryRow(ctx, `
SELECT count(*), min(target_set_hash)
FROM tunnel_connector_rotation_targets
WHERE operation_id = $1 AND account_id = $2 AND tunnel_id = $3`, plan.OperationID, plan.AccountID, plan.TunnelID).Scan(&capturedCount, &capturedHash); err != nil {
				return translate(err)
			}
			if capturedCount != len(plan.Targets) || capturedHash != plan.TargetSetHash {
				return fmt.Errorf("%w: immutable rotation target set changed", ErrGenerationConflict)
			}
		}
		// Rotation is a request for a new host-proven credential generation.
		// Until each host presents its signed identity and installs the new
		// reference, the currently active credentials remain authoritative. The
		// service never fabricates a keychain path or verifier thumbprint.
		changed := len(connectors) > 0
		outcome := "unchanged"
		if changed {
			outcome = "changed"
		}
		phase := "connecting"
		if changed {
			result, err = advanceResourceOperation(ctx, q, op.ID, input.TunnelID, phase, 60, input.Now)
		} else {
			result, err = completeResourceOperation(ctx, q, op.ID, input.TunnelID, "ready", outcome, input.Now)
		}
		if err != nil {
			return err
		}
		if err := recordResourceChange(ctx, q, resourceAuditInput{AuditEventID: input.AuditEventID, ParentAuditEventID: input.ParentAuditEventID, AccountID: input.AccountID,
			ActorID: auditActorID(input.ActorID, input.AuditActorID), ActorType: input.ActorType, EventType: "connector.credential_rotation_requested", ParentEventType: "tunnel.connector_credential_rotation_requested",
			ResourceType: "tunnel", ResourceID: input.TunnelID, TunnelID: input.TunnelID, OperationID: op.ID, IdempotencyKey: input.IdempotencyKey, RequestID: input.RequestID,
			CorrelationID: input.CorrelationID, SourceDeviceID: input.SourceDeviceID, Now: input.Now,
			Metadata: map[string]any{"connector_count": len(connectors), "target_set_hash": rotationTargetSetHash, "overlap_until": input.OverlapUntil.UTC().Format(time.RFC3339Nano), "credentials_retained_until_proof": true}, Message: "credential rotation scheduled; hosts must present a new verified identity"}); err != nil {
			return err
		}
		return nil
	})
	return result, translate(err)
}

func validateRotationRecord(input RotationRecord) error {
	for name, value := range map[string]string{"operation_id": input.OperationID, "audit_event_id": input.AuditEventID, "account_id": input.AccountID, "tunnel_id": input.TunnelID, "idempotency_key": input.IdempotencyKey, "actor_id": input.ActorID, "actor_type": input.ActorType, "correlation_id": input.CorrelationID} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%w: %s is required", ErrInvalidInput, name)
		}
	}
	if input.ExpectedGeneration < 1 || input.RequestHash == ([sha256.Size]byte{}) || !validActorType(input.ActorType) || !input.OverlapUntil.After(input.Now) || input.CredentialLifetime < time.Hour || input.CredentialLifetime > connectorprotocol.MaxRotationCredentialLifetime || !input.Now.Add(input.CredentialLifetime).After(input.OverlapUntil) {
		return fmt.Errorf("%w: invalid credential rotation", ErrInvalidInput)
	}
	return nil
}

func (r *SQLRepository) ListResourceTunnelLogs(ctx context.Context, accountID, tunnelID string, after int64, limit int) ([]dbsqlc.ListTunnelLogsV1Row, error) {
	if strings.TrimSpace(accountID) == "" || strings.TrimSpace(tunnelID) == "" || after < 0 || limit < 1 || limit > previewtunnelapi.MaximumPageLimit+1 {
		return nil, ErrInvalidInput
	}
	rows, err := r.db.Queries().ListTunnelLogsV1(ctx, dbsqlc.ListTunnelLogsV1Params{AccountID: accountID, TunnelID: nullableString(tunnelID), AfterSequence: sql.NullInt64{Int64: after, Valid: true}, RowLimit: int32(limit)})
	return rows, translate(err)
}

func (r *SQLRepository) ListResourcePreviewLogs(ctx context.Context, accountID, previewID string, after int64, limit int) ([]dbsqlc.TunnelLogEntry, error) {
	if strings.TrimSpace(accountID) == "" || strings.TrimSpace(previewID) == "" || after < 0 || limit < 1 || limit > previewtunnelapi.MaximumPageLimit+1 {
		return nil, ErrInvalidInput
	}
	rows, err := r.db.Queries().ListPreviewLogsV1(ctx, dbsqlc.ListPreviewLogsV1Params{AccountID: accountID, PreviewID: nullableString(previewID), AfterSequence: sql.NullInt64{Int64: after, Valid: true}, RowLimit: int32(limit)})
	return rows, translate(err)
}
