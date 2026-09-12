package teams

import (
	"context"

	"github.com/pinksaucepasta/paperboat-server/internal/db"
)

// revokeDepartingResourcesTx runs under the team authority lock, in the same
// transaction as departure. An empty account means the entire team is deleted.
// Personal resources and independent Git credentials remain personally owned.
func revokeDepartingResourcesTx(ctx context.Context, tx *db.Tx, team, account string) error {
	for _, query := range []string{
		`UPDATE team_resource_bindings b SET active=false,generation=b.generation+1
WHERE b.team_id=$1 AND b.active AND ($2='' OR (b.owner_account=$2 AND b.resource_kind<>'env'
AND NOT (b.resource_kind='machine' AND EXISTS(SELECT 1 FROM user_machines m WHERE m.id=b.resource_id AND m.owner_team_id=$1))))`,
		`UPDATE team_resource_grants g SET active=false,generation=g.generation+1
WHERE g.team_id=$1 AND g.active AND EXISTS(SELECT 1 FROM team_resource_bindings b WHERE b.team_id=g.team_id AND b.resource_kind=g.resource_kind AND b.resource_id=g.resource_id AND NOT b.active) AND $2::text IS NOT NULL`,
		`UPDATE team_terminal_session_grants g SET active=false,generation=g.generation+1
WHERE g.team_id=$1 AND g.active AND EXISTS(SELECT 1 FROM team_resource_bindings b WHERE b.team_id=g.team_id AND b.resource_kind='terminal_session' AND b.resource_id=g.terminal_session_id AND NOT b.active) AND $2::text IS NOT NULL`,
		`UPDATE team_inbox_requests SET status='revoked',decision_generation=decision_generation+1,updated_at=now()
WHERE team_id=$1 AND status IN ('pending','approved','consumed') AND ($2='' OR sender_account=$2 OR recipient_account=$2
OR NOT team_machine_capability_allowed(sender_account,team_id,destination_machine_id,'files'))`,
		`UPDATE control_config_assignments a SET consent_state='revoked',revoked_at=now(),approved_pull_revision=NULL,approved_at=NULL,version=a.version+1,updated_at=now()
FROM user_machines m WHERE a.machine_id=m.id AND a.adopted_team_id=$1 AND a.revoked_at IS NULL AND ($2='' OR m.user_id=$2)`,
		`DELETE FROM team_config_default_adoptions WHERE team_id=$1 AND ($2='' OR account_id=$2)`,
		`DELETE FROM team_config_defaults WHERE team_id=$1 AND $2=''`,
		`DELETE FROM team_receipt_smtp WHERE team_id=$1 AND $2=''`,
	} {
		if _, err := tx.Exec(ctx, query, team, account); err != nil {
			return err
		}
	}
	return nil
}
