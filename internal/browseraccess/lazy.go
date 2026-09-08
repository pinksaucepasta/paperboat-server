package browseraccess

import (
	"context"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/db"
)

// Dormant authority deliberately does not require a live daemon or touch the
// origin. Only the current owner, installation and exact policy confer access;
// activation reports offline status after this authorization succeeds.
const lazyPolicySQL = `SELECT p.id,p.account_id,p.access_mode,p.generation,p.expires_at
FROM lazy_access_policies p JOIN user_machines m ON m.id=p.machine_id AND m.user_id=p.account_id
WHERE p.hostname=$1 AND ($2='' OR p.id=$2) AND ($3='' OR p.id=$3)
 AND p.deleted_at IS NULL AND p.expires_at>$4
 AND m.environment_id=p.environment_id AND m.installation_generation=p.installation_generation
 AND m.deleted_at IS NULL AND m.revoked_at IS NULL AND m.seat_state='occupied'
 AND m.state NOT IN ('pending','revoked','deleted')`

// LazyPreviewSQL resolves only the current ready lease of an exact policy
// generation. A supplied preview/route additionally fences daemon refreshes so
// an old decision cannot move to a replacement lease. Callers must independently
// authorize the viewer before using this mapping.
const LazyPreviewSQL = `SELECT v.id,x.route_id,x.route_generation,
 LEAST(v.lease_deadline,COALESCE(v.user_deadline,v.lease_deadline),x.expires_at,p.expires_at,o.expires_at)
FROM lazy_access_policies p
JOIN lazy_activations a ON a.policy_id=p.id AND a.policy_generation=p.generation AND a.state='ready'
JOIN lazy_runtime_owners o ON o.machine_id=p.machine_id AND o.account_id=p.account_id
 AND o.installation_generation=p.installation_generation AND o.boot_id=a.boot_id
JOIN user_machines m ON m.id=p.machine_id AND m.user_id=p.account_id
JOIN preview_leases v ON v.id=a.preview_id AND v.account_id=p.account_id
JOIN preview_lease_carrier_attachments x ON x.preview_id=v.id AND x.account_id=v.account_id
WHERE p.id=$1 AND p.generation=$2 AND ($3='' OR v.id=$3) AND ($4='' OR x.route_id=$4)
 AND p.deleted_at IS NULL AND p.expires_at>$5 AND o.expires_at>$5
 AND m.environment_id=p.environment_id AND m.installation_generation=p.installation_generation
 AND m.deleted_at IS NULL AND m.revoked_at IS NULL AND m.seat_state='occupied'
 AND m.online AND m.state='online'
 AND v.owner_device_id=p.machine_id AND v.target_scheme=p.target_scheme AND v.target_address=p.target_address
 AND v.access_mode=p.access_mode AND v.endpoint='https://'||p.hostname
 AND v.terminal_state='active' AND v.lease_deadline>$5 AND (v.user_deadline IS NULL OR v.user_deadline>$5)
 AND x.state='ready' AND x.edge_ready AND x.origin_ready AND x.expires_at>$5 AND x.lease_generation=v.generation
LIMIT 1`

func storedSelectors(ctx context.Context, tx *db.Tx, storedKind, storedID string, generation int64, kind, id, route string, now time.Time) (string, string, string, error) {
	if storedKind != "lazy_policy" {
		return kind, id, route, nil
	}
	if kind == "lazy_policy" && (id == "" || id == storedID) && (route == "" || route == storedID) {
		return storedKind, storedID, storedID, nil
	}
	if kind != "preview" || id == "" || route == "" {
		return "", "", "", ErrNotAuthorized
	}
	var preview, currentRoute string
	var routeGeneration int64
	var expiry time.Time
	if err := tx.QueryRow(ctx, LazyPreviewSQL, storedID, generation, id, route, now).Scan(&preview, &currentRoute, &routeGeneration, &expiry); err != nil {
		return "", "", "", mapMissing(err)
	}
	return storedKind, storedID, storedID, nil
}
