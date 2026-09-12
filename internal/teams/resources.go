package teams

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
)

func (s *Service) Grant(ctx context.Context, account, team string, r GrantRequest) (Team, error) {
	if !validID(r.AccountID) || !validID(r.ResourceID) || !permits(r.ResourceKind, r.Permission, r.Permission) {
		return Team{}, ErrInvalid
	}
	return s.mutate(ctx, account, team, r.OperationID, "grant", r.ExpectedGeneration, r, func(ctx context.Context, tx *db.Tx, t Team, m Member) error {
		if !administrative(m.Role) {
			return ErrForbidden
		}
		if _, ok := member(t, r.AccountID); !ok {
			return ErrForbidden
		}
		var binding bool
		err := tx.QueryRow(ctx, `SELECT active FROM team_resource_bindings WHERE team_id=$1 AND resource_kind=$2 AND resource_id=$3`, team, r.ResourceKind, r.ResourceID).Scan(&binding)
		if errors.Is(err, pgx.ErrNoRows) || err == nil && !binding {
			return ErrForbidden
		}
		if err != nil {
			return err
		}
		if r.ResourceKind == "env" && r.ResourceID != team {
			return ErrInvalid
		}
		_, err = tx.Exec(ctx, `INSERT INTO team_resource_grants(team_id,account_id,resource_kind,resource_id,permission,generation,active) VALUES($1,$2,$3,$4,$5,1,$6) ON CONFLICT(team_id,account_id,resource_kind,resource_id,permission) DO UPDATE SET generation=team_resource_grants.generation+1,active=EXCLUDED.active`, team, r.AccountID, r.ResourceKind, r.ResourceID, r.Permission, r.Active)
		if err != nil {
			return err
		}
		if r.ResourceKind == "env" && !r.Active {
			var held bool
			if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM environment_vault_team_members WHERE team_id=$1 AND account_id=$2 AND grant_epoch>0)`, team, r.AccountID).Scan(&held); err != nil {
				return err
			}
			if _, err = tx.Exec(ctx, `UPDATE environment_vault_team_members SET grant_epoch=0 WHERE team_id=$1 AND account_id=$2`, team, r.AccountID); err != nil {
				return err
			}
			if _, err = tx.Exec(ctx, `DELETE FROM environment_vault_team_grants WHERE team_id=$1 AND account_id=$2`, team, r.AccountID); err != nil {
				return err
			}
			if held {
				return FenceENVTx(ctx, tx, team)
			}
		}
		if r.ResourceKind == "env" {
			return InvalidateENVTx(ctx, tx, team)
		}
		return nil
	})
}

// Attach is explicit authorization by the existing personal resource owner. It
// neither transfers the resource nor enables execution, and grants no member use.
func (s *Service) Attach(ctx context.Context, account, team string, r AttachRequest) (Team, error) {
	if !validID(r.ResourceID) || (r.ResourceKind != "preview" && r.ResourceKind != "tunnel" && r.ResourceKind != "lazy_policy") {
		return Team{}, ErrInvalid
	}
	return s.mutate(ctx, account, team, r.OperationID, "attach", r.ExpectedGeneration, r, func(ctx context.Context, tx *db.Tx, t Team, m Member) error {
		if !administrative(m.Role) {
			return ErrForbidden
		}
		query := `SELECT account_id FROM tunnels WHERE id=$1 AND deleted_at IS NULL FOR UPDATE`
		if r.ResourceKind == "preview" {
			query = `SELECT account_id FROM preview_leases WHERE id=$1 AND terminal_state='active' AND lease_deadline>now() FOR UPDATE`
		}
		if r.ResourceKind == "lazy_policy" {
			query = `SELECT account_id FROM lazy_access_policies WHERE id=$1 AND deleted_at IS NULL AND expires_at>now() FOR UPDATE`
		}
		var owner string
		err := tx.QueryRow(ctx, query, r.ResourceID).Scan(&owner)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if owner != account {
			return ErrForbidden
		}
		var count int
		var exists bool
		if err = tx.QueryRow(ctx, `SELECT count(*),coalesce(bool_or(resource_kind=$2 AND resource_id=$3),false) FROM team_resource_bindings WHERE team_id=$1`, team, r.ResourceKind, r.ResourceID).Scan(&count, &exists); err != nil {
			return err
		}
		if !exists && count >= MaximumResources {
			return ErrLimit
		}
		if _, err = tx.Exec(ctx, `INSERT INTO team_resource_bindings(team_id,resource_kind,resource_id,owner_account,active,generation) VALUES($1,$2,$3,$4,$5,1) ON CONFLICT(team_id,resource_kind,resource_id) DO UPDATE SET active=EXCLUDED.active,generation=team_resource_bindings.generation+1`, team, r.ResourceKind, r.ResourceID, owner, r.Active); err != nil {
			return err
		}
		if !r.Active {
			_, err = tx.Exec(ctx, `UPDATE team_resource_grants SET active=false,generation=generation+1 WHERE team_id=$1 AND resource_kind=$2 AND resource_id=$3 AND active`, team, r.ResourceKind, r.ResourceID)
		}
		return err
	})
}
