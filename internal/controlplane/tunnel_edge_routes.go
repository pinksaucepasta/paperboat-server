package controlplane

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"

	"github.com/pinksaucepasta/paperboat-server/internal/connectorprotocol"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
)

// TunnelEdgeRouteAssignmentRequest is the immutable binding used when a
// connector-ready route is published to an edge process. The origin address
// is intentionally absent: it belongs to the connector's authenticated
// configuration snapshot and is never an edge dialing target.
type TunnelEdgeRouteAssignmentRequest struct {
	AssignmentID               string
	AssignmentGeneration       int64
	AccountID                  string
	TunnelID                   string
	ConnectorID                string
	ConnectorGeneration        int64
	ConnectorSessionID         string
	ConnectorProcessGeneration int64
	ConfigGeneration           int64
	ConfigContentHash          []byte
	EdgeNodeID                 string
	EdgeProcessEpoch           string
	RouteID                    string
}

func (s *EdgeService) StageTunnelEdgeRouteAssignmentV1(ctx context.Context, request TunnelEdgeRouteAssignmentRequest) (dbsqlc.TunnelEdgeRouteAssignment, error) {
	if err := validateTunnelEdgeRouteAssignmentRequest(request); err != nil {
		return dbsqlc.TunnelEdgeRouteAssignment{}, err
	}
	if s == nil || s.store == nil {
		return dbsqlc.TunnelEdgeRouteAssignment{}, ErrAssignmentForbidden
	}
	row, err := s.store.Queries().StageTunnelEdgeRouteAssignmentV1(ctx, dbsqlc.StageTunnelEdgeRouteAssignmentV1Params{
		AssignmentID: request.AssignmentID, AssignmentGeneration: request.AssignmentGeneration, Now: s.clock().UTC(),
		AccountID: request.AccountID, ConnectorID: request.ConnectorID, ConnectorSessionID: request.ConnectorSessionID,
		ConfigGeneration: request.ConfigGeneration, EdgeNodeID: request.EdgeNodeID, EdgeProcessEpoch: request.EdgeProcessEpoch,
		RouteID: request.RouteID, TunnelID: request.TunnelID, ConnectorGeneration: request.ConnectorGeneration,
		ConnectorProcessGeneration: request.ConnectorProcessGeneration, ConfigContentHash: append([]byte(nil), request.ConfigContentHash...),
	})
	if errors.Is(err, sql.ErrNoRows) {
		return dbsqlc.TunnelEdgeRouteAssignment{}, ErrAssignmentConflict
	}
	return row, err
}

func (s *EdgeService) ActivateTunnelEdgeRouteAssignmentV1(ctx context.Context, assignmentID, routeID string) (dbsqlc.ActivateTunnelEdgeRouteAssignmentV1Row, error) {
	if !validTunnelEdgeIdentifier(assignmentID) || !validTunnelEdgeIdentifier(routeID) || s == nil || s.store == nil {
		return dbsqlc.ActivateTunnelEdgeRouteAssignmentV1Row{}, ErrAssignmentInvalid
	}
	row, err := s.store.Queries().ActivateTunnelEdgeRouteAssignmentV1(ctx, dbsqlc.ActivateTunnelEdgeRouteAssignmentV1Params{
		AssignmentID: assignmentID, RouteID: routeID, Now: s.clock().UTC(),
	})
	if errors.Is(err, sql.ErrNoRows) {
		return dbsqlc.ActivateTunnelEdgeRouteAssignmentV1Row{}, ErrAssignmentConflict
	}
	return row, err
}

func (s *EdgeService) ListTunnelEdgeRouteAssignmentsForNodeV1(ctx context.Context, nodeID, processEpoch string) ([]dbsqlc.ListTunnelEdgeRouteAssignmentsForNodeV1Row, error) {
	if !validTunnelEdgeIdentifier(nodeID) || !validTunnelEdgeProcessEpoch(processEpoch) || s == nil || s.store == nil {
		return nil, ErrAssignmentInvalid
	}
	rows, err := s.store.Queries().ListTunnelEdgeRouteAssignmentsForNodeV1(ctx, dbsqlc.ListTunnelEdgeRouteAssignmentsForNodeV1Params{
		EdgeNodeID: nodeID, EdgeProcessEpoch: processEpoch, Now: sql.NullTime{Time: s.clock().UTC(), Valid: true},
	})
	return rows, err
}

func validateTunnelEdgeRouteAssignmentRequest(request TunnelEdgeRouteAssignmentRequest) error {
	for _, value := range []string{request.AccountID, request.TunnelID, request.ConnectorID, request.ConnectorSessionID, request.EdgeNodeID, request.RouteID} {
		if !validTunnelEdgeIdentifier(value) {
			return ErrAssignmentInvalid
		}
	}
	if !validTunnelEdgeIdentifier(request.AssignmentID) || !validTunnelEdgeProcessEpoch(request.EdgeProcessEpoch) ||
		request.AssignmentGeneration < 1 || request.ConnectorGeneration < 1 || request.ConnectorProcessGeneration < 1 ||
		request.ConfigGeneration < 1 || len(request.ConfigContentHash) != 32 {
		return ErrAssignmentInvalid
	}
	return nil
}

func validTunnelEdgeIdentifier(value string) bool {
	if value != strings.TrimSpace(value) || len(value) < 3 || len(value) > 128 {
		return false
	}
	for index, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '_' || character == '.' || character == ':' || character == '-' {
			if index == 0 && (character < '0' || character > '9') && (character < 'A' || character > 'Z') && (character < 'a' || character > 'z') {
				return false
			}
			continue
		}
		return false
	}
	return true
}

func validTunnelEdgeProcessEpoch(value string) bool {
	if value != strings.TrimSpace(value) || len(value) < 8 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func tunnelEdgeRouteJSON(row dbsqlc.ListTunnelEdgeRouteAssignmentsForNodeV1Row) map[string]any {
	// The target is an opaque connector route binding. The edge must open the
	// canonical stream on the authenticated connector; it must never dial the
	// host-local origin address from this projection.
	return map[string]any{
		"assignment_id":                row.AssignmentID,
		"assignment_generation":        row.AssignmentGeneration,
		"route_id":                     row.RouteID,
		"route_revision":               row.RouteRevision,
		"account_id":                   row.AccountID,
		"host_id":                      row.HostID,
		"machine_identity_public_key":  row.MachineIdentityPublicKey,
		"machine_identity_thumbprint":  row.MachineIdentityThumbprint,
		"tunnel_id":                    row.TunnelID,
		"connector_id":                 row.ConnectorID,
		"connector_generation":         row.ConnectorGeneration,
		"connector_session_id":         row.ConnectorSessionID,
		"connector_process_generation": row.ConnectorProcessGeneration,
		"config_generation":            row.ConfigGeneration,
		"config_content_hash":          "sha256:" + hex.EncodeToString(row.ConfigContentHash),
		"access_mode":                  row.AccessMode,
		"edge_node_id":                 row.EdgeNodeID,
		"edge_process_epoch":           row.EdgeProcessEpoch,
		"edge_failure_domain":          row.EdgeFailureDomain,
		"kind":                         row.Kind,
		"public_host":                  row.PublicHost,
		"match_type":                   row.MatchType,
		"match_hostname":               nullableTunnelEdgeText(row.MatchHostname),
		"wildcard_suffix":              nullableTunnelEdgeText(row.WildcardSuffix),
		"path_prefix":                  nullableTunnelEdgeText(row.PathPrefix),
		"priority":                     row.Priority,
		"protocol":                     row.Protocol,
		"origin_scheme":                row.OriginScheme,
		"preserve_host":                row.PreserveHost,
		"host_override":                nullableTunnelEdgeText(row.HostOverride),
		"domain_bindings":              json.RawMessage([]byte(row.DomainBindings)),
		"state":                        row.State,
		"desired_state":                row.RouteDesiredState,
		"observed_state":               row.ObservedState,
		"target": map[string]any{
			"route_id":                     row.RouteID,
			"connector_session_id":         row.ConnectorSessionID,
			"connector_process_generation": row.ConnectorProcessGeneration,
			"config_generation":            row.ConfigGeneration,
		},
	}
}

func canonicalMachineIdentityThumbprint(encoded string) (string, error) {
	publicKey, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return "", ErrAssignmentInvalid
	}
	thumbprint, err := connectorprotocol.IdentityThumbprint(ed25519.PublicKey(publicKey))
	if err != nil {
		return "", ErrAssignmentInvalid
	}
	return thumbprint, nil
}

func nullableTunnelEdgeText(value sql.NullString) any {
	if !value.Valid {
		return nil
	}
	return value.String
}
