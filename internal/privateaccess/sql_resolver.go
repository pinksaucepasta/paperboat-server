package privateaccess

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
)

// SQLResolver is the production account-scoped resolver. Preview rows are
// read through the canonical preview attachment repository while durable
// tunnel rows, route rows, and the current connector session are checked in a
// single SQL statement. Every call rechecks current state and expiry.
type SQLResolver struct {
	db      *db.DB
	preview *PreviewAttachmentResolver
	clock   func() time.Time
}

func NewSQLResolver(database *db.DB, attachments AttachmentStore) (*SQLResolver, error) {
	if database == nil || database.Pool() == nil {
		return nil, fmt.Errorf("%w: private access database is not open", ErrInvalid)
	}
	preview, err := NewPreviewAttachmentResolver(attachments)
	if err != nil {
		return nil, err
	}
	return &SQLResolver{db: database, preview: preview, clock: func() time.Time { return time.Now().UTC() }}, nil
}

func (r *SQLResolver) SetClock(now func() time.Time) error {
	if r == nil || now == nil {
		return fmt.Errorf("%w: SQL resolver clock is required", ErrInvalid)
	}
	r.clock = now
	return r.preview.SetClock(now)
}

func (r *SQLResolver) ResolvePrivate(ctx context.Context, lookup Lookup) (Binding, error) {
	if r == nil || r.db == nil || r.db.Pool() == nil || ctx == nil {
		return Binding{}, ErrIdentityUnavailable
	}
	if err := lookup.Edge.Validate(); err != nil {
		return Binding{}, newDenied(ReasonIdentityInvalid)
	}
	if err := lookup.Request.Validate(); err != nil {
		return Binding{}, err
	}
	if lookup.AccountID == "" || lookup.AccountID != lookup.Request.AccountID {
		return Binding{}, newDenied(ReasonAccountMismatch)
	}
	if lookup.Request.ResourceKind == ResourcePreview {
		return r.preview.ResolvePrivate(ctx, lookup)
	}
	if lookup.Request.ResourceKind != ResourceTunnel {
		return Binding{}, ErrResourceNotFound
	}
	now := lookup.Now
	if now.IsZero() {
		now = r.clock().UTC()
	}
	return r.resolveTunnel(ctx, lookup, now)
}

func (r *SQLResolver) resolveTunnel(ctx context.Context, lookup Lookup, now time.Time) (Binding, error) {
	request := lookup.Request
	// A tunnel route is private only when both the durable tunnel and exact
	// route are active. The connector and session are required to be the
	// current accepting/ready pair, so a stale reconnect cannot authorize.
	row := r.db.Pool().QueryRow(ctx, resolvePrivateTunnelSQL,
		lookup.AccountID, request.ResourceID, request.RouteID, request.ConnectorID,
		request.CarrierSessionID, now, now.Add(MaximumDecisionTTL), lookup.Edge.NodeID, lookup.Edge.ProcessEpoch,
	)
	var (
		accountID, tunnelID, routeID, connectorID, sessionID                                                      string
		protocol, accessMode, tunnelState, routeState, connectorState, drainState, sessionState                   string
		generation, routeGeneration, sessionGeneration, processGeneration, configGeneration, assignmentGeneration int64
		expiresAt                                                                                                 time.Time
		hostname, pathPrefix                                                                                      string
		edgeNodeID, edgeProcessEpoch                                                                              string
	)
	if err := row.Scan(&accountID, &tunnelID, &routeID, &connectorID, &sessionID, &generation, &routeGeneration, &sessionGeneration, &processGeneration, &configGeneration, &assignmentGeneration, &protocol, &accessMode, &tunnelState, &routeState, &connectorState, &drainState, &sessionState, &expiresAt, &hostname, &pathPrefix, &edgeNodeID, &edgeProcessEpoch); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Binding{}, ErrResourceNotFound
		}
		return Binding{}, ErrRouteUnavailable
	}
	if accountID != lookup.AccountID || tunnelID != request.ResourceID || routeID != request.RouteID || connectorID != request.ConnectorID || sessionID != request.CarrierSessionID {
		return Binding{}, ErrResourceNotFound
	}
	if tunnelState != "active" || routeState != "active" || connectorState != "active" || drainState != "accepting" || sessionState != "ready" {
		return Binding{}, ErrRouteUnavailable
	}
	if accessMode != "private" {
		return Binding{}, newDenied(ReasonProtocolDenied)
	}
	if generation < 1 || routeGeneration < 1 || sessionGeneration < 1 || processGeneration < 1 || configGeneration < 1 || assignmentGeneration < 1 || !expiresAt.After(now) {
		return Binding{}, newDenied(ReasonExpired)
	}
	if protocol == "private_tcp" {
		protocol = ProtocolTCP
	} else if protocol == "http" {
		protocol = ProtocolHTTP
	} else {
		return Binding{}, newDenied(ReasonProtocolDenied)
	}
	if strings.HasPrefix(hostname, "https://") {
		hostname = hostFromEndpoint(hostname)
	}
	return Binding{
		AccountID: accountID, ResourceKind: ResourceTunnel, ResourceID: tunnelID, RouteID: routeID,
		ConnectorID: connectorID, CarrierSessionID: sessionID, RouteGeneration: uint64(routeGeneration),
		SessionGeneration: uint64(sessionGeneration), ProcessGeneration: uint64(processGeneration), ConfigGeneration: uint64(configGeneration), AssignmentGeneration: uint64(assignmentGeneration), Protocol: protocol,
		AccessMode: accessMode, State: "ready", ExpiresAt: expiresAt, Hostname: hostname, PathPrefix: pathPrefix,
		EdgeNodeID: edgeNodeID, EdgeProcessEpoch: edgeProcessEpoch,
	}, nil
}

const resolvePrivateTunnelSQL = `
SELECT t.account_id, t.id, r.id, c.id, s.id,
       t.generation, r.generation, assignment.connector_generation, s.process_generation,
	       c.last_applied_config_generation, assignment.assignment_generation, r.protocol, t.access_mode,
       t.desired_state, r.desired_state, c.desired_state, c.drain_state, s.state,
       LEAST(COALESCE(t.expires_at, $7), s.lease_deadline),
       COALESCE(r.match_hostname, t.stable_endpoint), COALESCE(r.path_prefix, ''),
       assignment.edge_node_id, assignment.edge_process_epoch
FROM tunnels AS t
JOIN tunnel_routes AS r ON r.tunnel_id = t.id
JOIN tunnel_connectors AS c ON c.tunnel_id = t.id
	JOIN tunnel_connector_sessions AS s ON s.connector_id = c.id
	JOIN tunnel_config_generations AS config
	  ON config.tunnel_id = t.id
	 AND config.generation = c.last_applied_config_generation
	 AND config.activation_state = 'active'
	JOIN tunnel_edge_route_assignments AS assignment
	  ON assignment.route_id = r.id
	 AND assignment.account_id = t.account_id
	 AND assignment.tunnel_id = t.id
	 AND assignment.connector_id = c.id
	 AND assignment.host_id = c.host_id
	 AND assignment.connector_generation = c.generation
	 AND assignment.connector_session_id = s.id
	 AND assignment.connector_process_generation = s.process_generation
	 AND assignment.config_generation = config.generation
	 AND assignment.config_content_hash = config.content_hash
	 AND assignment.access_mode = t.access_mode
	 AND assignment.route_generation = r.generation
	 AND assignment.route_revision = r.generation
	 AND assignment.edge_node_id = $8
	 AND assignment.edge_process_epoch = $9
	 AND assignment.state = 'active'
	 AND assignment.observed_state = 'ready'
	JOIN control_tunnel_nodes AS edge_node
	  ON edge_node.id = assignment.edge_node_id
	 AND edge_node.process_epoch = assignment.edge_process_epoch
	JOIN user_machines AS machine
	  ON machine.id = c.host_id
	 AND machine.user_id = t.account_id
WHERE t.account_id = $1
  AND t.id = $2
  AND r.id = $3
  AND c.id = $4
  AND s.id = $5
  AND t.access_mode = 'private'
  AND t.deleted_at IS NULL
  AND r.deleted_at IS NULL
  AND c.revoked_at IS NULL
	AND c.last_session_id = s.id
	AND c.last_applied_config_generation = s.applied_config_generation
	AND c.ready_at IS NOT NULL
	AND s.ready_at IS NOT NULL
	AND machine.state = 'online'
	AND machine.online
	AND machine.deleted_at IS NULL
	AND machine.revoked_at IS NULL
	AND edge_node.state = 'ready'
	AND edge_node.ready = true
	AND edge_node.last_heartbeat_at IS NOT NULL
	AND edge_node.last_heartbeat_at > $6 - interval '2 minutes'
	AND s.lease_deadline > $6
  AND (t.expires_at IS NULL OR t.expires_at > $6)
	AND c.last_heartbeat_at > $6 - interval '2 minutes'
	AND s.last_heartbeat_at > $6 - interval '2 minutes'
FOR SHARE OF t, r, c, s`
