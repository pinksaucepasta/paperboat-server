package teams

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
)

func capacity(ctx context.Context, tx *db.Tx, account, team string) error {
	var users, members int
	err := tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM team_members m JOIN teams t USING(team_id) WHERE m.account_id=$1 AND m.active AND t.deleted_at IS NULL),(SELECT count(*) FROM team_members WHERE team_id=$2 AND account_id<>$1)`, account, team).Scan(&users, &members)
	if err != nil {
		return err
	}
	if users >= MaximumMembers || members >= MaximumMembers {
		return ErrLimit
	}
	return nil
}
func (s *Service) Create(ctx context.Context, account string, r CreateRequest) (Team, error) {
	var out Team
	if !validID(r.TeamID) {
		return out, ErrInvalid
	}
	err := s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		if err := Lock(ctx, tx); err != nil {
			return err
		}
		done, digest, err := replay(ctx, tx, account, r.OperationID, "create", r, &out)
		if err != nil {
			return err
		}
		if done {
			current, e := ReadTx(ctx, tx, r.TeamID)
			if e != nil {
				return e
			}
			m, ok := member(current, account)
			if !ok || current.Deleted || m.Role != "owner" {
				return ErrForbidden
			}
			out = current
			return nil
		}
		if err = capacity(ctx, tx, account, r.TeamID); err != nil {
			return err
		}
		var exists bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM teams WHERE team_id=$1)`, r.TeamID).Scan(&exists); err != nil {
			return err
		}
		if exists {
			return ErrConflict
		}
		if _, err = tx.Exec(ctx, `INSERT INTO teams(team_id,owner_account,generation) VALUES($1,$2,1)`, r.TeamID, account); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `INSERT INTO team_members(team_id,account_id,membership_generation,role,active) VALUES($1,$2,1,'member',true)`, r.TeamID, account); err != nil {
			return err
		}
		out, err = ReadTx(ctx, tx, r.TeamID)
		if err != nil {
			return err
		}
		if err = AuditTx(ctx, tx, account, r.TeamID, "create", r.OperationID, nil); err != nil {
			return err
		}
		return save(ctx, tx, account, r.OperationID, digest, out)
	})
	return out, err
}
func (s *Service) mutate(ctx context.Context, account, team, op, kind string, expected uint64, request any, apply func(context.Context, *db.Tx, Team, Member) error) (Team, error) {
	var out Team
	if !validID(team) {
		return out, ErrInvalid
	}
	err := s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		if err := Lock(ctx, tx); err != nil {
			return err
		}
		done, digest, err := replay(ctx, tx, account, op, kind, []any{team, request}, &out)
		if err != nil {
			return err
		}
		t, err := ReadTx(ctx, tx, team)
		if err != nil {
			return err
		}
		if done {
			if kind == "terminal_session_grant" || kind == "terminal_session_end" {
				var session string
				if r, ok := request.(TerminalSessionGrantRequest); ok {
					session = r.TerminalSessionID
				}
				var owner string
				if err := tx.QueryRow(ctx, `SELECT owner_account FROM team_resource_bindings WHERE team_id=$1 AND resource_kind='terminal_session' AND resource_id=$2`, team, session).Scan(&owner); err != nil || owner != account {
					return ErrForbidden
				}
			} else if err := replayAuthority(t, out, account, kind, request); err != nil {
				return err
			}
			out = t
			return nil
		}
		m, err := check(t, account, expected)
		if err != nil {
			return err
		}
		if err = apply(ctx, tx, t, m); err != nil {
			return err
		}
		if err = advance(ctx, tx, team); err != nil {
			return err
		}
		out, err = ReadTx(ctx, tx, team)
		if err != nil {
			return err
		}
		metadata := map[string]any{"generation": out.Generation}
		switch r := request.(type) {
		case MutationRequest:
			metadata["target_account"] = r.AccountID
			metadata["role"] = r.Role
		case GrantRequest:
			metadata["target_account"] = r.AccountID
			metadata["resource_kind"] = r.ResourceKind
			metadata["resource_id"] = r.ResourceID
			metadata["permission"] = r.Permission
			metadata["active"] = r.Active
		case MachineGrantRequest:
			metadata["machine_id"] = r.MachineID
			metadata["target_account"] = r.AccountID
			metadata["audience"] = r.Audience
			metadata["capabilities"] = r.Capabilities
			metadata["active"] = r.Active
		case TerminalSessionGrantRequest:
			metadata["terminal_session_id"] = r.TerminalSessionID
			metadata["target_account"] = r.AccountID
			metadata["audience"] = r.Audience
			metadata["role"] = r.Role
			metadata["active"] = r.Active
		case MachineRequest:
			metadata["machine_id"] = r.MachineID
			metadata["action"] = r.Action
		case AttachRequest:
			metadata["resource_kind"] = r.ResourceKind
			metadata["resource_id"] = r.ResourceID
			metadata["active"] = r.Active
		}
		if err = AuditTx(ctx, tx, account, team, kind, op, metadata); err != nil {
			return err
		}
		return save(ctx, tx, account, op, digest, out)
	})
	return out, err
}
func (s *Service) Mutate(ctx context.Context, account, team string, r MutationRequest) (Team, error) {
	return s.mutate(ctx, account, team, r.OperationID, r.Action, r.ExpectedGeneration, r, func(ctx context.Context, tx *db.Tx, t Team, actor Member) error {
		target, found := member(t, r.AccountID)
		switch r.Action {
		case "role":
			if actor.Role != "owner" || !found || target.Role == "owner" {
				return ErrForbidden
			}
			if r.Role != "admin" && r.Role != "member" {
				return ErrInvalid
			}
			if r.Role == "member" {
				if _, err := tx.Exec(ctx, `UPDATE team_invitations SET cancelled_at=now() WHERE team_id=$1 AND created_by=$2 AND accepted_at IS NULL AND cancelled_at IS NULL`, team, r.AccountID); err != nil {
					return err
				}
			}
			_, err := tx.Exec(ctx, `UPDATE team_members SET role=$3 WHERE team_id=$1 AND account_id=$2`, team, r.AccountID, r.Role)
			return err
		case "remove":
			if !administrative(actor.Role) || !found || target.Role == "owner" || (actor.Role == "admin" && target.Role != "member") {
				return ErrForbidden
			}
			return RemoveMemberTx(ctx, tx, team, r.AccountID)
		case "leave":
			if actor.Role == "owner" {
				return ErrForbidden
			}
			if r.AccountID != "" && r.AccountID != account {
				return ErrInvalid
			}
			return RemoveMemberTx(ctx, tx, team, account)
		case "transfer":
			if actor.Role != "owner" || !found || r.AccountID == account {
				return ErrForbidden
			}
			if _, err := tx.Exec(ctx, `UPDATE team_members SET role='member' WHERE team_id=$1 AND account_id IN($2,$3)`, team, account, r.AccountID); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE team_invitations SET cancelled_at=now() WHERE team_id=$1 AND created_by=$2 AND accepted_at IS NULL AND cancelled_at IS NULL`, team, account); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `UPDATE teams SET owner_account=$2 WHERE team_id=$1`, team, r.AccountID)
			return err
		case "delete":
			if actor.Role != "owner" {
				return ErrForbidden
			}
			if r.Confirmation != team {
				return ErrInvalid
			}
			if err := FenceENVTx(ctx, tx, team); err != nil {
				return err
			}
			if err := removeTeamMachinesTx(ctx, tx, team); err != nil {
				return err
			}
			if err := revokeDepartingResourcesTx(ctx, tx, team, ""); err != nil {
				return err
			}
			for _, q := range []string{`UPDATE team_terminal_session_grants SET active=false,generation=generation+1 WHERE team_id=$1 AND active`, `UPDATE team_machine_grants SET active=false,generation=generation+1 WHERE team_id=$1 AND active`, `UPDATE teams SET deleted_at=now() WHERE team_id=$1`, `UPDATE team_members SET active=false,membership_generation=membership_generation+1 WHERE team_id=$1 AND active`, `UPDATE team_resource_grants SET active=false,generation=generation+1 WHERE team_id=$1 AND active`, `UPDATE team_resource_bindings SET active=false,generation=generation+1 WHERE team_id=$1 AND active`, `UPDATE team_invitations SET cancelled_at=now() WHERE team_id=$1 AND accepted_at IS NULL AND cancelled_at IS NULL`, `DELETE FROM environment_vault_team_grants WHERE team_id=$1`, `DELETE FROM environment_vault_team_members WHERE team_id=$1`, `DELETE FROM environment_vault_scopes WHERE owner_kind='team' AND owner_id=$1`, `DELETE FROM environment_vault_teams WHERE team_id=$1`} {
				if _, err := tx.Exec(ctx, q, team); err != nil {
					return err
				}
			}
			return nil
		default:
			return ErrInvalid
		}
	})
}
func (s *Service) Invite(ctx context.Context, account, team string, r InviteRequest) (Invitation, error) {
	var out Invitation
	if !validID(r.AccountID) || !validID(team) {
		return out, ErrInvalid
	}
	err := s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		if err := Lock(ctx, tx); err != nil {
			return err
		}
		done, digest, err := replay(ctx, tx, account, r.OperationID, "invite", []any{team, r}, &out)
		if err != nil {
			return err
		}
		t, err := ReadTx(ctx, tx, team)
		if err != nil {
			return err
		}
		if done {
			m, ok := member(t, account)
			if !ok || t.Deleted || !administrative(m.Role) {
				return ErrForbidden
			}
			return nil
		}
		m, err := check(t, account, r.ExpectedGeneration)
		if err != nil {
			return err
		}
		if !administrative(m.Role) {
			return ErrForbidden
		}
		if _, ok := member(t, r.AccountID); ok {
			return ErrConflict
		}
		var user bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE id=$1 AND status='active')`, r.AccountID).Scan(&user); err != nil {
			return err
		}
		if !user {
			return ErrNotFound
		}
		if _, err = tx.Exec(ctx, `UPDATE team_invitations SET cancelled_at=now() WHERE team_id=$1 AND expires_at<=now() AND accepted_at IS NULL AND cancelled_at IS NULL`, team); err != nil {
			return err
		}
		var count int
		var exists bool
		if err = tx.QueryRow(ctx, `SELECT count(*),coalesce(bool_or(recipient_account=$2),false) FROM team_invitations WHERE team_id=$1 AND accepted_at IS NULL AND cancelled_at IS NULL`, team, r.AccountID).Scan(&count, &exists); err != nil {
			return err
		}
		if exists {
			return ErrConflict
		}
		if count >= MaximumInvitations {
			return ErrLimit
		}
		if err = capacity(ctx, tx, r.AccountID, team); err != nil {
			return err
		}
		var random [24]byte
		if _, err = rand.Read(random[:]); err != nil {
			return err
		}
		out = Invitation{InvitationID: "inv_" + hex.EncodeToString(random[:]), TeamID: team, AccountID: r.AccountID, Role: "member", Generation: t.Generation + 1}
		err = tx.QueryRow(ctx, `INSERT INTO team_invitations(invitation_id,team_id,recipient_account,created_by,expires_at) VALUES($1,$2,$3,$4,now()+$5*interval '1 second') RETURNING expires_at`, out.InvitationID, team, r.AccountID, account, int64(InvitationLifetime/time.Second)).Scan(&out.ExpiresAt)
		if err != nil {
			return err
		}
		if err = advance(ctx, tx, team); err != nil {
			return err
		}
		if err = AuditTx(ctx, tx, account, team, "invite", r.OperationID, map[string]any{"recipient_account": r.AccountID}); err != nil {
			return err
		}
		return save(ctx, tx, account, r.OperationID, digest, out)
	})
	return out, err
}
func (s *Service) Accept(ctx context.Context, account, id string, r AcceptRequest) (Team, error) {
	var out Team
	if !validID(id) {
		return out, ErrInvalid
	}
	err := s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		if err := Lock(ctx, tx); err != nil {
			return err
		}
		done, digest, err := replay(ctx, tx, account, r.OperationID, "accept", []any{id, r}, &out)
		if err != nil {
			return err
		}
		if done {
			current, e := ReadTx(ctx, tx, out.TeamID)
			if e != nil {
				return e
			}
			if _, ok := member(current, account); !ok || current.Deleted {
				return ErrForbidden
			}
			out = current
			return nil
		}
		var team, recipient string
		var expires time.Time
		var usable bool
		err = tx.QueryRow(ctx, `SELECT team_id,recipient_account,expires_at,accepted_at IS NULL AND cancelled_at IS NULL AND expires_at>now() FROM team_invitations WHERE invitation_id=$1 FOR UPDATE`, id).Scan(&team, &recipient, &expires, &usable)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if recipient != account {
			return ErrForbidden
		}
		if !usable {
			return ErrExpired
		}
		t, err := ReadTx(ctx, tx, team)
		if err != nil {
			return err
		}
		if t.Deleted {
			return ErrForbidden
		}
		if _, ok := member(t, account); ok {
			return ErrConflict
		}
		if err = capacity(ctx, tx, account, team); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `INSERT INTO team_members(team_id,account_id,membership_generation,role,active) VALUES($1,$2,1,'member',true) ON CONFLICT(team_id,account_id) DO UPDATE SET membership_generation=team_members.membership_generation+1,role='member',active=true`, team, account); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `UPDATE team_invitations SET accepted_at=now() WHERE invitation_id=$1`, id); err != nil {
			return err
		}
		if err = advance(ctx, tx, team); err != nil {
			return err
		}
		out, err = ReadTx(ctx, tx, team)
		if err != nil {
			return err
		}
		if err = AuditTx(ctx, tx, account, team, "accept", r.OperationID, nil); err != nil {
			return err
		}
		return save(ctx, tx, account, r.OperationID, digest, out)
	})
	return out, err
}
func (s *Service) CancelInvite(ctx context.Context, account, team, id string, r MutationRequest) (Team, error) {
	return s.mutate(ctx, account, team, r.OperationID, "cancel_invite", r.ExpectedGeneration, []any{id, r}, func(ctx context.Context, tx *db.Tx, t Team, m Member) error {
		if !administrative(m.Role) {
			return ErrForbidden
		}
		tag, err := tx.Exec(ctx, `UPDATE team_invitations SET cancelled_at=now() WHERE team_id=$1 AND invitation_id=$2 AND accepted_at IS NULL AND cancelled_at IS NULL`, team, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrExpired
		}
		return nil
	})
}

// Exact terminal-operation retries reconcile their already committed outcome.
// Other retries still require the actor's current administrative authority.
func replayAuthority(current, result Team, account, kind string, request any) error {
	if kind == "delete" || kind == "leave" || kind == "transfer" {
		if current.Generation != result.Generation {
			return ErrConflict
		}
		switch kind {
		case "delete":
			if current.Deleted && result.Deleted && current.OwnerAccount == account {
				return nil
			}
		case "leave":
			if _, ok := member(current, account); !ok && !current.Deleted {
				return nil
			}
		case "transfer":
			r, ok := request.(MutationRequest)
			if ok && !current.Deleted && current.OwnerAccount == r.AccountID {
				return nil
			}
		}
		return ErrForbidden
	}
	actor, ok := member(current, account)
	if !ok || current.Deleted || !administrative(actor.Role) {
		return ErrForbidden
	}
	if kind == "role" && actor.Role != "owner" {
		return ErrForbidden
	}
	if kind == "remove" && actor.Role == "admin" {
		r, ok := request.(MutationRequest)
		if !ok {
			return ErrInvalid
		}
		for _, m := range current.Members {
			if m.AccountID == r.AccountID && m.Role != "member" {
				return ErrForbidden
			}
		}
	}
	return nil
}
