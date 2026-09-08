-- name: ListEdgeDNSPublicationResourcesV1 :many
-- Paginate resources, not rows/addresses, so a batch cannot publish a partial set.
SELECT id, max(generation)::bigint AS generation FROM (
 SELECT id,generation FROM tunnels
 UNION ALL SELECT owner_id AS id,resource_generation AS generation FROM edge_dns_publications
) owners WHERE id > sqlc.arg(after_id)::text
GROUP BY id ORDER BY id LIMIT sqlc.arg(batch_size);

-- name: ListEdgeDNSPublicationNamesV1 :many
-- Managed endpoints and verified domain reservations share the tunnel's owner.
SELECT substring(t.stable_endpoint from 9)::text AS hostname
FROM tunnels t WHERE t.id=sqlc.arg(tunnel_id)
UNION
SELECT d.hostname FROM tunnel_domains d
WHERE d.tunnel_id=sqlc.arg(tunnel_id) AND d.ownership_state='verified'
 AND d.conflict_state='clear' AND d.deleted_at IS NULL
ORDER BY hostname LIMIT 129;

-- name: ListReadyEdgeDNSAddressesV1 :many
-- Every active route sharing the hostname must be usable on the advertised node.
-- An active connector alone is not certificate, listener or origin readiness.
SELECT DISTINCT node.id,t.generation AS resource_generation,statement_timestamp()::timestamptz AS observed_at, COALESCE(host(node.public_ingress_ipv4),'')::text AS ipv4,
 COALESCE(host(node.public_ingress_ipv6),'')::text AS ipv6,
 (node.process_epoch || '/' || COALESCE((
   SELECT string_agg(a.assignment_id,',' ORDER BY a.assignment_id)
   FROM tunnel_edge_route_assignments a WHERE a.tunnel_id=t.id AND a.edge_node_id=node.id
    AND a.edge_process_epoch=node.process_epoch AND a.state='active' AND a.observed_state='ready'
 ),'') || '/' || COALESCE((
   SELECT string_agg(cert.id,',' ORDER BY cert.id)
   FROM tunnel_certificate_records cert JOIN tunnel_certificate_edge_distributions d ON d.certificate_id=cert.id
   WHERE cert.state='active' AND d.edge_node_id=node.id AND d.edge_process_epoch=node.process_epoch
    AND d.state IN ('ready','active') AND (cert.tunnel_id=t.id OR cert.target_kind='platform_wildcard')
 ),''))::text AS readiness_version,
 LEAST(t.expires_at,node.registry_expires_at,node.last_heartbeat_at+interval '15 seconds',
   (SELECT min(LEAST(s.lease_deadline,s.last_heartbeat_at+interval '15 seconds'))
    FROM tunnel_edge_route_assignments a JOIN tunnel_connector_sessions s ON s.id=a.connector_session_id
    WHERE a.tunnel_id=t.id AND a.edge_node_id=node.id AND a.edge_process_epoch=node.process_epoch
     AND a.state='active' AND a.observed_state='ready'))::timestamptz AS valid_until
FROM tunnels t
JOIN control_tunnel_nodes node ON true
WHERE t.id=sqlc.arg(tunnel_id) AND t.desired_state='active' AND t.deleted_at IS NULL
 AND (t.expires_at IS NULL OR t.expires_at>sqlc.arg(now))
 AND t.access_mode IN ('public','private','team')
 AND node.state='ready' AND node.ready AND node.drain_deadline IS NULL
 AND node.roles @> ARRAY['edge']::text[]
 AND node.last_heartbeat_at>sqlc.arg(now)::timestamptz-interval '15 seconds'
 AND node.registry_expires_at>sqlc.arg(now)
 AND (node.allowed_account_ids IS NULL OR t.account_id=ANY(node.allowed_account_ids))
 AND node.public_ingress_verified_at IS NOT NULL
 AND (node.public_ingress_ipv4 IS NOT NULL OR node.public_ingress_ipv6 IS NOT NULL)
 AND EXISTS (SELECT 1 FROM tunnel_routes r WHERE r.tunnel_id=t.id AND r.desired_state='active' AND r.deleted_at IS NULL AND r.protocol IN ('http','tcp'))
 AND NOT EXISTS (
  SELECT 1 FROM tunnel_routes r
  WHERE r.tunnel_id=t.id AND r.desired_state='active' AND r.deleted_at IS NULL AND r.protocol IN ('http','tcp')
   AND NOT EXISTS (
    SELECT 1 FROM tunnel_edge_route_assignments a
    JOIN tunnel_connectors c ON c.id=a.connector_id AND c.tunnel_id=t.id
    JOIN tunnel_connector_sessions s ON s.id=a.connector_session_id AND s.connector_id=c.id
    JOIN tunnel_config_generations config ON config.tunnel_id=t.id AND config.generation=a.config_generation
    WHERE a.route_id=r.id AND a.route_generation=r.generation AND a.account_id=t.account_id
     AND a.state='active' AND a.observed_state='ready' AND a.access_mode=t.access_mode
     AND a.edge_node_id=node.id AND a.edge_process_epoch=node.process_epoch
     AND c.desired_state='active' AND c.drain_state='accepting' AND c.revoked_at IS NULL
     AND c.generation=a.connector_generation AND c.last_session_id=s.id
     AND c.last_applied_config_generation=a.config_generation
     AND s.state='ready' AND s.process_generation=a.connector_process_generation
     AND s.applied_config_generation=a.config_generation AND s.lease_deadline>sqlc.arg(now)
     AND s.last_heartbeat_at>sqlc.arg(now)::timestamptz-interval '15 seconds'
     AND config.activation_state='active' AND config.content_hash=a.config_content_hash
   )
 )
 AND (
  NOT EXISTS (SELECT 1 FROM tunnel_routes r WHERE r.tunnel_id=t.id AND r.desired_state='active' AND r.deleted_at IS NULL AND r.protocol IN ('http','tcp') AND r.protocol='http')
  OR EXISTS (
   SELECT 1 FROM tunnel_certificate_records cert
   JOIN tunnel_certificate_edge_distributions distribution ON distribution.certificate_id=cert.id
   WHERE cert.state='active' AND cert.revoked_at IS NULL AND cert.not_before<=sqlc.arg(now) AND cert.expires_at>sqlc.arg(now)
    AND (cert.tunnel_id=t.id OR cert.target_kind='platform_wildcard')
    AND (cert.hostname=sqlc.arg(hostname) OR
      (left(cert.hostname,2)='*.' AND substring(sqlc.arg(hostname)::text from position('.' in sqlc.arg(hostname)::text))=substring(cert.hostname from 2)))
    AND distribution.edge_node_id=node.id AND distribution.edge_process_epoch=node.process_epoch
    AND distribution.state IN ('ready','active')
    AND distribution.observed_certificate_generation=cert.certificate_generation
  )
 )
ORDER BY node.id LIMIT 3;

-- name: TransferWithdrawnEdgeDNSNameV1 :execrows
-- A new resource may acquire a released hostname only after verified removal
-- and only while the authoritative namespace currently belongs to it. Keep
-- the publication generation monotonic to fence delayed old-owner cleanup.
UPDATE edge_dns_publications p
SET owner_id=sqlc.arg(owner_id),resource_generation=sqlc.arg(resource_generation),
 publication_generation=publication_generation+1,readiness_version='',
 observed_at=sqlc.arg(observed_at),valid_until=NULL,state='desired',failure_code=NULL,
 verified_at=NULL,updated_at=statement_timestamp()
WHERE p.hostname=sqlc.arg(hostname) AND p.owner_id<>sqlc.arg(owner_id)
 AND p.state='verified' AND p.desired_addresses='[]'::jsonb AND p.provider_records='[]'::jsonb
 AND p.observed_at<=sqlc.arg(observed_at)
 AND (
  EXISTS (SELECT 1 FROM tunnels t WHERE t.id=sqlc.arg(owner_id) AND t.generation=sqlc.arg(resource_generation)
    AND t.deleted_at IS NULL AND t.desired_state<>'deleted' AND substring(t.stable_endpoint from 9)=p.hostname)
  OR EXISTS (SELECT 1 FROM tunnel_domains d JOIN tunnels t ON t.id=d.tunnel_id
    WHERE d.tunnel_id=sqlc.arg(owner_id) AND d.hostname=p.hostname AND d.deleted_at IS NULL
      AND d.ownership_state='verified' AND d.conflict_state='clear' AND t.deleted_at IS NULL
      AND t.desired_state<>'deleted' AND t.generation=sqlc.arg(resource_generation))
 );
