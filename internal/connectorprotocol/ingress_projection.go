package connectorprotocol

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/db"
)

const maximumIngressDecisions = 4096

// SQLIngressSource projects current publication authority; it owns no state.
// Existing tunnel tables represent durable resources. Ephemeral creation and
// public TCP allocation will supply their own persisted lifecycle fields.
type SQLIngressSource struct {
	DB    *db.DB
	Clock Clock
}

func (s SQLIngressSource) Daemon(ctx context.Context, active ActiveControlSession) ([]IngressDecision, error) {
	if active.validate() != nil {
		return nil, ErrInvalidInput
	}
	return s.project(ctx, active, "", "", "public", "")
}

func (s SQLIngressSource) Edge(ctx context.Context, nodeID, epoch string) ([]IngressDecision, error) {
	if ValidateIdentifier(nodeID) != nil || ValidateOpaqueEpoch(epoch) != nil {
		return nil, ErrInvalidInput
	}
	return s.project(ctx, ActiveControlSession{}, nodeID, epoch, "public", "")
}

// Both selectors are scoped: a complete authenticated daemon session or an
// exact edge process. No caller may request an account-wide/global projection.
const ingressProjectionSQL = `
SELECT t.account_id,environment.id,t.id,t.generation,r.id,r.generation,c.host_id,m.installation_generation,
 COALESCE(r.match_hostname,substring(t.stable_endpoint from 9)),CASE WHEN r.protocol='tcp' THEN '' ELSE COALESCE(r.path_prefix,'/') END,r.origin_scheme,r.origin_address,
 r.tls_verification,COALESCE(r.tls_server_name,''),COALESCE(r.ca_reference,''),COALESCE(r.mtls_credential_reference,''),
 COALESCE(r.public_tcp_listener_id,''),COALESCE(r.public_tcp_port,0),r.protocol,
 a.edge_node_id,a.edge_process_epoch,c.id,session.id,session.process_generation,
 config.generation,a.assignment_generation,
 LEAST($1::timestamptz + interval '10 seconds',session.lease_deadline,t.expires_at,identity.expires_at,credential.valid_until,node.registry_expires_at,node.last_heartbeat_at+interval '15 seconds',session.last_heartbeat_at+interval '15 seconds')
FROM tunnel_edge_route_assignments a
JOIN tunnels t ON t.id=a.tunnel_id AND t.account_id=a.account_id
JOIN tunnel_routes r ON r.id=a.route_id AND r.tunnel_id=t.id
JOIN tunnel_connectors c ON c.id=a.connector_id AND c.tunnel_id=t.id AND c.host_id=a.host_id
JOIN user_machines m ON m.id=c.host_id AND m.user_id=t.account_id
JOIN control_environments environment ON environment.id=m.environment_id AND environment.owner_user_id=t.account_id AND environment.workspace_id=m.id
JOIN machine_control_sessions identity ON identity.machine_id=m.id AND identity.installation_generation=m.installation_generation
JOIN tunnel_connector_sessions session ON session.id=a.connector_session_id AND session.connector_id=c.id
JOIN tunnel_connector_credential_generations credential ON credential.connector_id=c.id AND credential.tunnel_id=t.id AND credential.generation=session.credential_generation
JOIN tunnel_config_generations config ON config.tunnel_id=t.id AND config.generation=a.config_generation
JOIN control_tunnel_nodes node ON node.id=a.edge_node_id AND node.process_epoch=a.edge_process_epoch
WHERE a.state='active' AND a.observed_state='ready'
 AND t.desired_state='active' AND t.deleted_at IS NULL AND (t.expires_at IS NULL OR t.expires_at>$1)
 AND environment.desired_state='active' AND environment.revoked_at IS NULL
 AND t.access_mode=$13 AND a.access_mode=t.access_mode AND ($14::text='' OR r.id=$14)
 AND r.desired_state='active' AND r.deleted_at IS NULL AND r.protocol IN ('http','tcp')
 AND r.generation=a.route_generation AND (r.match_type IN ('managed','exact') OR ($13<>'public' AND r.match_type='catch_all'))
 AND ((r.protocol='http' AND r.origin_scheme IN ('http','https','h2c')) OR (r.protocol='tcp' AND r.origin_scheme='tcp'))
 AND r.tls_verification IN ('not_applicable','system','custom_ca')
 AND c.desired_state='active' AND c.revoked_at IS NULL AND c.drain_state='accepting'
 AND c.generation=a.connector_generation AND c.last_session_id=session.id
 AND c.last_applied_config_generation=a.config_generation
 AND m.deleted_at IS NULL AND m.revoked_at IS NULL AND m.state NOT IN ('pending','revoked','deleted')
 AND m.seat_state='occupied' AND m.public_identity_key=a.machine_identity_public_key
 AND identity.issued_at<=$1 AND identity.expires_at>$1
 AND credential.state IN ('active','overlap') AND credential.revoked_at IS NULL AND credential.valid_until>$1
 AND session.state='ready' AND session.process_generation=a.connector_process_generation
 AND session.last_heartbeat_at>$1::timestamptz-interval '15 seconds' AND session.lease_deadline>$1
 AND session.applied_config_generation=a.config_generation
 AND config.activation_state='active' AND config.content_hash=a.config_content_hash
 AND node.registry_expires_at>$1 AND node.roles @> ARRAY['edge']::text[]
 AND node.drain_deadline IS NULL
 AND (node.allowed_account_ids IS NULL OR t.account_id=ANY(node.allowed_account_ids))
 AND node.state='ready' AND node.ready=true AND node.last_heartbeat_at>$1::timestamptz-interval '15 seconds'
 AND (($2::text<>'' AND t.account_id=$2 AND t.id=$3 AND c.id=$4 AND c.host_id=$5
       AND session.id=$6 AND session.process_generation=$7 AND config.generation=$8
       AND 'sha256:'||encode(config.content_hash,'hex')=$9 AND session.credential_generation=$10)
      OR ($2::text='' AND $11::text<>'' AND node.id=$11 AND node.process_epoch=$12))
ORDER BY a.route_id,a.assignment_generation,a.assignment_id
LIMIT 4097`

func (s SQLIngressSource) project(ctx context.Context, active ActiveControlSession, nodeID, epoch, audience, routeID string) ([]IngressDecision, error) {
	if ctx == nil || s.DB == nil || s.DB.SQL() == nil {
		return nil, ErrInvalidInput
	}
	now := time.Now().UTC()
	if s.Clock != nil {
		now = s.Clock.Now().UTC()
	}
	rows, err := s.DB.SQL().QueryContext(ctx, ingressProjectionSQL, now, active.AccountID, active.TunnelID, active.ConnectorID, active.HostID, active.SessionID, active.ProcessGeneration, active.ConfigGeneration, active.ConfigContentHash, active.CredentialGeneration, nodeID, epoch, audience, routeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]IngressDecision, 0)
	for rows.Next() {
		if len(out) == maximumIngressDecisions {
			return nil, ErrIngressDenied
		}
		var d IngressDecision
		b := &d.Binding
		if err = rows.Scan(&b.AccountID, &b.EnvironmentID, &b.TunnelID, &b.ResourceGeneration, &b.RouteID, &b.RouteGeneration, &b.HostID, &b.InstallationGeneration, &b.Hostname, &b.PathPrefix, &b.OriginScheme, &b.OriginAddress, &b.TLSVerification, &b.TLSServerName, &b.CAReference, &b.MTLSCredentialReference, &b.ListenerID, &b.PublicPort, &b.Protocol, &d.EdgeNodeID, &d.EdgeProcessEpoch, &d.ConnectorID, &d.SessionID, &d.ProcessGeneration, &d.ConfigGeneration, &d.AssignmentGeneration, &d.ExpiresAt); err != nil {
			return nil, err
		}
		if err = completeIngressProjection(&d, now); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func completeIngressProjection(d *IngressDecision, now time.Time) error {
	b := &d.Binding
	// Route owns its exact target and owner publication in the existing schema;
	// these aliases preserve generation fencing without inventing another owner.
	b.TargetID = b.RouteID
	b.TargetGeneration = b.RouteGeneration
	b.PublicationID = b.RouteID
	b.PublicationGeneration = b.RouteGeneration
	b.Lifecycle = TunnelDurable
	b.Audience = "public"
	b.ConnectionMethod = "edge"
	host, port, err := net.SplitHostPort(b.OriginAddress)
	if err != nil {
		return ErrIngressDenied
	}
	if host == "localhost" {
		host = "127.0.0.1"
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return ErrIngressDenied
	}
	b.OriginAddress = net.JoinHostPort(ip.String(), port)
	d.PolicyGeneration = b.ResourceGeneration
	d.Action = "view"
	d.IssuedAt = now
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return err
	}
	d.DecisionID = "ingress_" + hex.EncodeToString(nonce[:])
	return d.Validate(now)
}

// RestrictedRoute returns the exact current connector/target projection only.
// The caller must compose it with independently checked browser grant authority;
// this method never issues a viewer grant or trusts a claimed principal.
func (s SQLIngressSource) RestrictedRoute(ctx context.Context, nodeID, epoch, audience, routeID string) (IngressDecision, error) {
	if ValidateIdentifier(nodeID) != nil || ValidateOpaqueEpoch(epoch) != nil || ValidateIdentifier(routeID) != nil || (audience != "private" && audience != "team") {
		return IngressDecision{}, ErrIngressDenied
	}
	rows, err := s.project(ctx, ActiveControlSession{}, nodeID, epoch, audience, routeID)
	if err != nil {
		return IngressDecision{}, err
	}
	if len(rows) != 1 {
		return IngressDecision{}, ErrIngressDenied
	}
	rows[0].Binding.Audience = audience
	return rows[0], nil
}
