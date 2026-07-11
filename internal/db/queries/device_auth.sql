-- name: CreateDeviceGrant :exec
INSERT INTO device_grants
(id, client_id, client_label, device_type, os, scopes, device_code_hash, user_code_hash, state, issued_at, expires_at, poll_interval_seconds, next_poll_at, created_network_hash)
VALUES (sqlc.arg(id), sqlc.arg(client_id), sqlc.arg(client_label), sqlc.arg(device_type), sqlc.arg(os), string_to_array(sqlc.arg(scopes),' '), sqlc.arg(device_code_hash), sqlc.arg(user_code_hash), 'pending', sqlc.arg(issued_at), sqlc.arg(expires_at), sqlc.arg(poll_interval_seconds), sqlc.arg(issued_at), sqlc.arg(created_network_hash));

-- name: GetDeviceGrantForPoll :one
SELECT id,client_id,state,coalesce(user_id,'') AS user_id,client_label,device_type,os,array_to_string(scopes,' ') AS scopes,expires_at,next_poll_at,poll_interval_seconds,device_code_hash
FROM device_grants WHERE device_code_hash = ANY(string_to_array($1,' ')) FOR UPDATE;

-- name: ExpireDeviceGrant :exec
UPDATE device_grants SET state='expired',version=version+1 WHERE id=$1 AND state IN ('pending','approved');

-- name: GetUserStatus :one
SELECT status FROM users WHERE id=$1;

-- name: DenyApprovedDeviceGrant :exec
UPDATE device_grants SET state='denied',denied_at=$2,version=version+1 WHERE id=$1 AND state='approved';

-- name: SlowDeviceGrantPoll :exec
UPDATE device_grants SET poll_interval_seconds=$2,next_poll_at=$3,version=version+1 WHERE id=$1;

-- name: AdvanceDeviceGrantPoll :exec
UPDATE device_grants SET next_poll_at=$2,version=version+1 WHERE id=$1;

-- name: GetDeviceGrantApprovedAt :one
SELECT approved_at FROM device_grants WHERE id=$1;

-- name: CreateClientSession :exec
INSERT INTO client_sessions (id,user_id,client_id,client_label,device_type,os,scopes,state,created_at,approved_at)
VALUES (sqlc.arg(id),sqlc.arg(user_id),sqlc.arg(client_id),sqlc.arg(client_label),sqlc.arg(device_type),sqlc.arg(os),string_to_array(sqlc.arg(scopes),' '),'active',sqlc.arg(created_at),sqlc.arg(approved_at));

-- name: CreateClientAccessToken :exec
INSERT INTO client_access_tokens (token_hash,client_session_id,expires_at,created_at) VALUES ($1,$2,$3,$4);

-- name: CreateClientRefreshToken :exec
INSERT INTO client_refresh_tokens (token_hash,client_session_id,state,expires_at,created_at) VALUES ($1,$2,'active',$3,$4);

-- name: ConsumeDeviceGrant :execrows
UPDATE device_grants SET state='consumed',consumed_at=$2,version=version+1 WHERE id=$1 AND state='approved';

-- name: GetDeviceGrantRequest :one
SELECT client_label,device_type,os,array_to_string(scopes,' ') AS scopes,issued_at,expires_at,state,user_code_hash
FROM device_grants WHERE user_code_hash = ANY(string_to_array($1,' '));

-- name: GetDeviceGrantForDecision :one
SELECT id,state,coalesce(user_id,'') AS user_id,expires_at,user_code_hash,client_id
FROM device_grants WHERE user_code_hash = ANY(string_to_array($1,' ')) FOR UPDATE;

-- name: ExpireDeviceGrantWithoutVersion :exec
UPDATE device_grants SET state='expired' WHERE id=$1 AND state IN ('pending','approved');

-- name: ApproveDeviceGrant :exec
UPDATE device_grants SET state='approved',user_id=$2,approved_at=$3,version=version+1 WHERE id=$1 AND state='pending';

-- name: DenyDeviceGrant :exec
UPDATE device_grants SET state='denied',user_id=$2,denied_at=$3,version=version+1 WHERE id=$1 AND state='pending';

-- name: AuthenticateClientAccessToken :one
SELECT cs.id,array_to_string(cs.scopes,' ') AS scopes,u.id AS user_id,u.workos_subject,u.primary_email,u.display_name,u.status,u.role,u.created_at
FROM client_access_tokens t JOIN client_sessions cs ON cs.id=t.client_session_id JOIN users u ON u.id=cs.user_id
WHERE t.token_hash = ANY(string_to_array(sqlc.arg(token_hashes),' ')) AND t.revoked_at IS NULL AND t.expires_at>sqlc.arg(now) AND cs.state='active' AND u.status='active';

-- name: TouchClientSession :exec
UPDATE client_sessions SET last_used_at=$2 WHERE id=$1;

-- name: GetClientRefreshTokenForUpdate :one
SELECT rt.client_session_id,rt.state,rt.expires_at,array_to_string(cs.scopes,' ') AS scopes,rt.token_hash
FROM client_refresh_tokens rt JOIN client_sessions cs ON cs.id=rt.client_session_id
WHERE rt.token_hash = ANY(string_to_array($1,' ')) FOR UPDATE OF rt,cs;

-- name: MarkClientRefreshTokenRotated :exec
UPDATE client_refresh_tokens SET state='rotated',rotated_at=$2 WHERE token_hash=$1;

-- name: FindClientSessionByToken :one
SELECT client_session_id FROM client_access_tokens WHERE token_hash = ANY(string_to_array($1,' '))
UNION SELECT client_session_id FROM client_refresh_tokens WHERE token_hash = ANY(string_to_array($1,' ')) LIMIT 1;

-- name: GetClientSessionIdentity :one
SELECT user_id,client_id FROM client_sessions WHERE id=$1;

-- name: RevokeClientSession :exec
UPDATE client_sessions SET state='revoked',revoked_at=coalesce(revoked_at,$2),revocation_reason=coalesce(revocation_reason,$3),version=version+1 WHERE id=$1;

-- name: RevokeClientAccessTokens :exec
UPDATE client_access_tokens SET revoked_at=coalesce(revoked_at,$2) WHERE client_session_id=$1;

-- name: RevokeClientRefreshTokens :exec
UPDATE client_refresh_tokens SET state='revoked',revoked_at=coalesce(revoked_at,$2) WHERE client_session_id=$1 AND state<>'revoked';

-- name: GetClientSessionOwnerForUpdate :one
SELECT user_id FROM client_sessions WHERE id=$1 FOR UPDATE;

-- name: CountClientSessions :one
SELECT count(*) FROM client_sessions WHERE user_id=sqlc.arg(user_id) AND (sqlc.arg(state_filter)::text='' OR state=sqlc.arg(state_filter));

-- name: ListClientSessions :many
SELECT id,client_id,client_label,device_type,os,array_to_string(scopes,' ') AS scopes,state,created_at,approved_at,last_used_at,revoked_at,revocation_reason
FROM client_sessions WHERE user_id=sqlc.arg(user_id) AND (sqlc.arg(state_filter)::text='' OR state=sqlc.arg(state_filter)) ORDER BY created_at DESC LIMIT sqlc.arg(row_limit) OFFSET sqlc.arg(row_offset);

-- name: TakeAuthRateLimit :one
WITH cleanup AS (DELETE FROM auth_rate_limits WHERE auth_rate_limits.window_start < sqlc.arg(cutoff))
INSERT INTO auth_rate_limits(bucket_key,window_start,request_count) VALUES(sqlc.arg(bucket_key),sqlc.arg(rate_window),1)
ON CONFLICT(bucket_key,window_start) DO UPDATE SET request_count=auth_rate_limits.request_count+1 RETURNING request_count;
