package nativeprivateaccess

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/db"
)

type SQLResolver struct {
	database *sql.DB
	now      func() time.Time
}

func NewSQLResolver(database *db.DB) (*SQLResolver, error) {
	if database == nil || database.SQL() == nil {
		return nil, ErrInvalid
	}
	return &SQLResolver{database: database.SQL(), now: func() time.Time { return time.Now().UTC() }}, nil
}

// ResolveNativePrivate selects only desired state owned by the authenticated
// account and reachable through the caller's current machine-access session.
// It does not join edge assignments, connectors, or public routes.
func (r *SQLResolver) ResolveNativePrivate(ctx context.Context, in Request) (Target, error) {
	if r == nil || r.database == nil || ctx == nil || in.AccountID == "" || in.UserID != in.AccountID || in.CLIClientSessionID == "" {
		return Target{}, ErrInvalid
	}
	now := r.now()
	var out Target
	if in.ResourceKind == "preview" {
		err := r.database.QueryRowContext(ctx, `SELECT p.account_id,a.user_id,a.environment_id,p.owner_device_id,a.id,'preview',p.id,p.id,'http',p.target_scheme,p.target_address,p.generation,p.generation,p.generation
FROM paperboat.preview_leases p
JOIN paperboat.user_machine_access_sessions a ON a.user_id=p.account_id AND a.user_machine_id=p.owner_device_id AND a.cli_client_session_id=$1 AND a.state='active' AND a.revoked_at IS NULL AND a.expires_at>$2 AND a.helper_terminal_session_id IS NOT NULL
WHERE p.account_id=$3 AND p.id=$4 AND p.id=$5 AND $6='http' AND p.access_mode='private' AND p.terminal_state='active' AND p.lease_deadline>$2`, in.CLIClientSessionID, now, in.AccountID, in.ResourceID, in.RouteID, in.Protocol).Scan(&out.AccountID, &out.UserID, &out.EnvironmentID, &out.MachineID, &out.AccessSessionID, &out.ResourceKind, &out.ResourceID, &out.RouteID, &out.Protocol, &out.TargetScheme, &out.TargetAddress, &out.ResourceGeneration, &out.RouteGeneration, &out.TargetGeneration)
		return out, mapResolveError(err)
	}
	if in.ResourceKind != "tunnel" {
		if in.Selector == "" {
			return Target{}, ErrDenied
		}
		in.ResourceKind, in.Protocol = "tunnel", "tcp"
	}
	query := `SELECT t.account_id,a.user_id,a.environment_id,t.created_by_host_id,a.id,'tunnel',t.id,r.id,CASE WHEN r.protocol='private_tcp' THEN 'tcp' ELSE 'http' END,r.origin_scheme,r.origin_address,t.generation,r.generation,r.generation
FROM paperboat.tunnels t
JOIN paperboat.tunnel_routes r ON r.tunnel_id=t.id
JOIN paperboat.user_machine_access_sessions a ON a.user_id=t.account_id AND a.user_machine_id=t.created_by_host_id AND a.cli_client_session_id=$1 AND a.state='active' AND a.revoked_at IS NULL AND a.expires_at>$2 AND a.helper_terminal_session_id IS NOT NULL
WHERE t.account_id=$3 AND (($4='' AND t.id=$5 AND r.id=$6 AND (CASE WHEN r.protocol='private_tcp' THEN 'tcp' ELSE 'http' END)=$7) OR ($4<>'' AND r.protocol='private_tcp' AND (t.id=$4 OR r.id=$4 OR t.name=$4 OR r.name=$4))) AND t.access_mode='private' AND t.desired_state='active' AND t.deleted_at IS NULL AND (t.expires_at IS NULL OR t.expires_at>$2) AND r.desired_state='active' AND r.deleted_at IS NULL
ORDER BY t.id,r.id LIMIT 2`
	rows, err := r.database.QueryContext(ctx, query, in.CLIClientSessionID, now, in.AccountID, in.Selector, in.ResourceID, in.RouteID, in.Protocol)
	if err != nil {
		return Target{}, mapResolveError(err)
	}
	defer rows.Close()
	if !rows.Next() {
		return Target{}, ErrDenied
	}
	if err = rows.Scan(&out.AccountID, &out.UserID, &out.EnvironmentID, &out.MachineID, &out.AccessSessionID, &out.ResourceKind, &out.ResourceID, &out.RouteID, &out.Protocol, &out.TargetScheme, &out.TargetAddress, &out.ResourceGeneration, &out.RouteGeneration, &out.TargetGeneration); err != nil {
		return Target{}, mapResolveError(err)
	}
	if rows.Next() {
		return Target{}, ErrDenied
	}
	return out, mapResolveError(rows.Err())
}
func mapResolveError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return ErrDenied
	}
	return fmt.Errorf("resolve native private target: %w", err)
}
