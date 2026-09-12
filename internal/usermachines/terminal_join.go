package usermachines

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"regexp"

	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/teams"
)

type TerminalJoinObservation struct {
	AccessSessionID   string `json:"access_session_id"`
	TerminalSessionID string `json:"terminal_session_id"`
	AttachmentID      string `json:"attachment_id"`
}

var ErrTerminalJoinInvalid = errors.New("terminal join identifiers are invalid")
var terminalJoinID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)

// RecordTerminalJoin accepts only the current signed target host's successful
// attachment observation. The request cannot choose an actor, team or role.
func (s *Service) RecordTerminalJoin(ctx context.Context, environment, machine string, in TerminalJoinObservation) error {
	if !terminalJoinID.MatchString(in.AccessSessionID) || !terminalJoinID.MatchString(in.TerminalSessionID) || !terminalJoinID.MatchString(in.AttachmentID) {
		return ErrTerminalJoinInvalid
	}
	return s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		if err := teams.Lock(ctx, tx); err != nil {
			return err
		}
		var actor, team, role string
		err := tx.QueryRow(ctx, `SELECT a.user_id,a.team_id,a.terminal_role
FROM user_machine_access_sessions a
JOIN user_machines host ON host.id=a.user_machine_id
JOIN teams t ON t.team_id=a.team_id AND t.deleted_at IS NULL
JOIN team_members m ON m.team_id=t.team_id AND m.account_id=a.user_id AND m.active
JOIN team_resource_bindings b ON b.team_id=t.team_id AND b.resource_kind='terminal_session' AND b.resource_id=a.terminal_session_id AND b.active
LEFT JOIN team_terminal_session_grants selected ON selected.team_id=t.team_id AND selected.terminal_session_id=a.terminal_session_id AND selected.audience='selected_member' AND selected.account_id=a.user_id
LEFT JOIN team_terminal_session_grants all_members ON all_members.team_id=t.team_id AND all_members.terminal_session_id=a.terminal_session_id AND all_members.audience='all_members'
WHERE a.id=$1 AND a.terminal_session_id=$2 AND a.user_machine_id=$3 AND a.environment_id=$4
AND a.state='active' AND a.revoked_at IS NULL AND a.expires_at>now()
AND host.revoked_at IS NULL AND host.deleted_at IS NULL AND host.online AND host.state='online'
AND host.configured_capabilities @> ARRAY['terminal_host'] AND host.observed_capabilities @> ARRAY['terminal_host']
AND a.terminal_role IN ('viewer','interactive') AND terminal_session_role(a.user_id,a.terminal_session_id)=a.terminal_role
AND a.terminal_membership_generation=m.membership_generation AND a.terminal_binding_generation=b.generation
AND a.terminal_grant_generation=CASE WHEN selected.account_id IS NOT NULL THEN selected.generation ELSE all_members.generation END
AND a.terminal_team_generation=t.generation`, in.AccessSessionID, in.TerminalSessionID, machine, environment).Scan(&actor, &team, &role)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrTerminalSessionNotFound
		}
		if err != nil {
			return err
		}
		return teams.AuditTx(ctx, tx, actor, team, "terminal_session_joined", in.AccessSessionID+":"+in.AttachmentID, map[string]any{"terminal_session_id": in.TerminalSessionID, "access_session_id": in.AccessSessionID, "attachment_id": in.AttachmentID, "role": role})
	})
}
