package teams

import (
	"context"
	"database/sql"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
)

func (s *Service) GrantTerminalSession(ctx context.Context, account, team string, r TerminalSessionGrantRequest) (Team, error) {
	if !validID(r.TerminalSessionID) || (r.Active && r.RuntimeGeneration < 1) || (r.Audience != "all_members" && r.Audience != "selected_member") || (r.Role != "viewer" && r.Role != "interactive") || (r.Audience == "all_members" && r.AccountID != "") || (r.Audience == "selected_member" && !validID(r.AccountID)) {
		return Team{}, ErrInvalid
	}
	return s.mutate(ctx, account, team, r.OperationID, "terminal_session_grant", r.ExpectedGeneration, r, func(ctx context.Context, tx *db.Tx, t Team, _ Member) error {
		var owner string
		err := tx.QueryRow(ctx, `SELECT owner_account FROM user_machine_terminal_sessions WHERE id=$1 AND deleted_at IS NULL UNION ALL SELECT owner_account FROM project_terminal_sessions WHERE id=$1 AND deleted_at IS NULL LIMIT 1`, r.TerminalSessionID).Scan(&owner)
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if owner != account {
			return ErrForbidden
		}
		if r.Audience == "selected_member" {
			if _, ok := member(t, r.AccountID); !ok {
				return ErrForbidden
			}
		}
		var boundElsewhere bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM team_resource_bindings WHERE resource_kind='terminal_session' AND resource_id=$1 AND team_id<>$2 AND active)`, r.TerminalSessionID, team).Scan(&boundElsewhere); err != nil {
			return err
		}
		if boundElsewhere {
			return ErrConflict
		}
		var existingOwner string
		var existingActive bool
		var existingProcess sql.NullInt64
		err = tx.QueryRow(ctx, `SELECT owner_account,active,terminal_process_generation FROM team_resource_bindings WHERE team_id=$1 AND resource_kind='terminal_session' AND resource_id=$2`, team, r.TerminalSessionID).Scan(&existingOwner, &existingActive, &existingProcess)
		if errors.Is(err, pgx.ErrNoRows) {
			var count int
			if err = tx.QueryRow(ctx, `SELECT count(*) FROM team_resource_bindings WHERE team_id=$1`, team).Scan(&count); err != nil {
				return err
			}
			if count >= MaximumResources {
				return ErrLimit
			}
			_, err = tx.Exec(ctx, `INSERT INTO team_resource_bindings(team_id,resource_kind,resource_id,owner_account,active,generation,terminal_process_generation) VALUES($1,'terminal_session',$2,$3,true,1,$4)`, team, r.TerminalSessionID, account, r.RuntimeGeneration)
		} else if err != nil {
			return err
		} else if existingOwner != account {
			return ErrForbidden
		} else if r.Active && (!existingActive || !existingProcess.Valid || uint64(existingProcess.Int64) != r.RuntimeGeneration) {
			_, err = tx.Exec(ctx, `UPDATE team_resource_bindings SET active=true,generation=generation+1,terminal_process_generation=$3 WHERE team_id=$1 AND resource_kind='terminal_session' AND resource_id=$2`, team, r.TerminalSessionID, r.RuntimeGeneration)
			if err == nil {
				_, err = tx.Exec(ctx, `DELETE FROM team_terminal_session_grants WHERE team_id=$1 AND terminal_session_id=$2`, team, r.TerminalSessionID)
			}
		}
		if err != nil {
			return err
		}
		if r.Audience == "all_members" {
			_, err = tx.Exec(ctx, `INSERT INTO team_terminal_session_grants(team_id,terminal_session_id,audience,role,active) VALUES($1,$2,'all_members',$3,$4) ON CONFLICT(team_id,terminal_session_id) WHERE audience='all_members' DO UPDATE SET role=EXCLUDED.role,active=EXCLUDED.active,generation=team_terminal_session_grants.generation+1`, team, r.TerminalSessionID, r.Role, r.Active)
		} else {
			_, err = tx.Exec(ctx, `INSERT INTO team_terminal_session_grants(team_id,terminal_session_id,audience,account_id,role,active) VALUES($1,$2,'selected_member',$3,$4,$5) ON CONFLICT(team_id,terminal_session_id,account_id) WHERE audience='selected_member' DO UPDATE SET role=EXCLUDED.role,active=EXCLUDED.active,generation=team_terminal_session_grants.generation+1`, team, r.TerminalSessionID, r.AccountID, r.Role, r.Active)
		}
		return err
	})
}

func (s *Service) EndTerminalSessionSharing(ctx context.Context, account, team, session, operation string, expected uint64) (Team, error) {
	r := TerminalSessionGrantRequest{OperationID: operation, ExpectedGeneration: expected, TerminalSessionID: session}
	return s.mutate(ctx, account, team, operation, "terminal_session_end", expected, r, func(ctx context.Context, tx *db.Tx, _ Team, _ Member) error {
		var owner string
		err := tx.QueryRow(ctx, `SELECT owner_account FROM team_resource_bindings WHERE team_id=$1 AND resource_kind='terminal_session' AND resource_id=$2 AND active`, team, session).Scan(&owner)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if owner != account {
			return ErrForbidden
		}
		_, err = tx.Exec(ctx, `UPDATE team_resource_bindings SET active=false,generation=generation+1 WHERE team_id=$1 AND resource_kind='terminal_session' AND resource_id=$2 AND active`, team, session)
		return err
	})
}

func (s *Service) RemoveTerminalParticipant(ctx context.Context, account, team, session, target, operation string, expected uint64) (Team, error) {
	return s.GrantTerminalSession(ctx, account, team, TerminalSessionGrantRequest{OperationID: operation, ExpectedGeneration: expected, TerminalSessionID: session, Audience: "selected_member", AccountID: target, Role: "viewer", Active: false})
}

// ResolveTerminalSession returns an exact current shared-session decision.
// An inactive selected grant is a deliberate exclusion from an all-member grant.
func (s *Service) ResolveTerminalSession(ctx context.Context, account, session string) (TerminalSessionDecision, error) {
	var out TerminalSessionDecision
	err := s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		if err := Lock(ctx, tx); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `WITH source AS (
		 SELECT s.id,s.owner_account,'machine'::text target_kind,s.user_machine_id target_id,s.user_machine_id machine_id FROM user_machine_terminal_sessions s WHERE s.id=$2 AND s.deleted_at IS NULL
		 UNION ALL
			SELECT s.id,s.owner_account,'hosted',s.project_id,coalesce((SELECT m.id FROM user_machines m WHERE m.environment_id=s.project_id AND m.deleted_at IS NULL ORDER BY m.created_at DESC LIMIT 1),'') FROM project_terminal_sessions s WHERE s.id=$2 AND s.deleted_at IS NULL
		), candidate AS (
		 SELECT b.team_id,b.resource_id,t.generation team_generation,m.membership_generation,b.generation binding_generation,b.terminal_process_generation,src.owner_account,src.target_kind,src.target_id,src.machine_id,
		  selected.account_id selected_account,selected.active selected_active,selected.role selected_role,selected.generation selected_generation,
		  all_grant.active all_active,all_grant.role all_role,all_grant.generation all_generation
		 FROM source src JOIN team_resource_bindings b ON b.resource_kind='terminal_session' AND b.resource_id=src.id AND b.owner_account=src.owner_account AND b.active
		 JOIN teams t USING(team_id) JOIN team_members m ON m.team_id=b.team_id AND m.account_id=$1 AND m.active
		 LEFT JOIN team_terminal_session_grants selected ON selected.team_id=b.team_id AND selected.terminal_session_id=b.resource_id AND selected.audience='selected_member' AND selected.account_id=$1
		 LEFT JOIN team_terminal_session_grants all_grant ON all_grant.team_id=b.team_id AND all_grant.terminal_session_id=b.resource_id AND all_grant.audience='all_members'
		 WHERE t.deleted_at IS NULL)
		SELECT team_id,resource_id,CASE WHEN selected_account IS NOT NULL THEN CASE WHEN selected_active THEN selected_role END ELSE CASE WHEN all_active THEN all_role END END,target_kind,target_id,machine_id,owner_account,team_generation,membership_generation,binding_generation,CASE WHEN selected_account IS NOT NULL THEN selected_generation ELSE all_generation END,terminal_process_generation
		FROM candidate WHERE CASE WHEN selected_account IS NOT NULL THEN selected_active ELSE all_active END ORDER BY team_id LIMIT 1`, account, session).Scan(&out.TeamID, &out.SessionID, &out.Role, &out.TargetKind, &out.TargetID, &out.MachineID, &out.OwnerAccount, &out.TeamGeneration, &out.MembershipGeneration, &out.BindingGeneration, &out.GrantGeneration, &out.ProcessGeneration)
	})
	if errors.Is(err, pgx.ErrNoRows) || errors.Is(err, sql.ErrNoRows) {
		return out, ErrNotFound
	}
	return out, err
}
