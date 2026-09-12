package controlplane

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
	"github.com/pinksaucepasta/paperboat-server/internal/teams"
)

type ConfigTeamDefaultView struct {
	TeamID               string `json:"team_id"`
	Provider             string `json:"provider"`
	ExternalRepositoryID string `json:"external_repository_id"`
	DisplayName          string `json:"display_name"`
	Branch               string `json:"branch"`
	Version              int64  `json:"version"`
}

type ConfigTeamDefaultAdoptionView struct {
	ConfigTeamDefaultView
	RepositoryID   string `json:"repository_id"`
	AdoptedVersion int64  `json:"adopted_version"`
	UpdatePending  bool   `json:"update_pending"`
}

func (s *ConfigAssignmentService) TeamDefault(ctx context.Context, userID, teamID string) (ConfigTeamDefaultView, error) {
	if !s.teamMember(ctx, userID, teamID) {
		return ConfigTeamDefaultView{}, ErrAssignmentForbidden
	}
	item, err := s.store.Queries().GetTeamConfigDefault(ctx, teamID)
	if errors.Is(err, sql.ErrNoRows) {
		return ConfigTeamDefaultView{}, ErrAssignmentForbidden
	}
	return teamDefaultView(item), err
}

func (s *ConfigAssignmentService) SetTeamDefault(ctx context.Context, userID, teamID, repositoryID string, expectedVersion int64) (ConfigTeamDefaultView, error) {
	if expectedVersion < 0 {
		return ConfigTeamDefaultView{}, ErrAssignmentForbidden
	}
	var item dbsqlc.TeamConfigDefault
	err := s.store.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		if err := teams.Lock(ctx, tx); err != nil {
			return err
		}
		if !teamAdministratorTx(ctx, tx, userID, teamID) {
			return ErrAssignmentForbidden
		}
		repository, err := tx.Queries().GetOwnedControlConfigRepository(ctx, dbsqlc.GetOwnedControlConfigRepositoryParams{ID: strings.TrimSpace(repositoryID), OwnerUserID: userID})
		if err != nil || !repository.ExternalRepositoryID.Valid || !repository.DefaultBranch.Valid {
			return ErrAssignmentForbidden
		}
		current, currentErr := tx.Queries().GetTeamConfigDefault(ctx, teamID)
		if errors.Is(currentErr, sql.ErrNoRows) {
			if expectedVersion != 0 {
				return ErrAssignmentConflict
			}
		} else if currentErr != nil {
			return currentErr
		} else if current.Version != expectedVersion {
			return ErrAssignmentConflict
		}
		item, err = tx.Queries().SetTeamConfigDefault(ctx, dbsqlc.SetTeamConfigDefaultParams{
			TeamID: teamID, Provider: repository.Provider, ExternalRepositoryID: repository.ExternalRepositoryID.String,
			DisplayName: repository.DisplayName, Branch: repository.DefaultBranch.String, UpdatedBy: userID, ExpectedVersion: expectedVersion,
		})
		if errors.Is(err, sql.ErrNoRows) {
			return ErrAssignmentConflict
		}
		if err != nil {
			return err
		}
		return teams.AuditTx(ctx, tx, userID, teamID, "config_default_changed", fmt.Sprintf("config-default-change:%d:%d", item.Version, item.UpdatedAt.UnixNano()), map[string]any{"repository_id": repository.ID, "version": item.Version})
	})
	return teamDefaultView(item), err
}

func (s *ConfigAssignmentService) DeleteTeamDefault(ctx context.Context, userID, teamID string, expectedVersion int64) error {
	if expectedVersion < 1 {
		return ErrAssignmentForbidden
	}
	err := s.store.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		if err := teams.Lock(ctx, tx); err != nil {
			return err
		}
		if !teamAdministratorTx(ctx, tx, userID, teamID) {
			return ErrAssignmentForbidden
		}
		deleted, err := tx.Queries().DeleteTeamConfigDefault(ctx, dbsqlc.DeleteTeamConfigDefaultParams{TeamID: teamID, ExpectedVersion: expectedVersion})
		if errors.Is(err, sql.ErrNoRows) {
			return ErrAssignmentConflict
		}
		if err != nil {
			return err
		}
		return teams.AuditTx(ctx, tx, userID, teamID, "config_default_deleted", fmt.Sprintf("config-default-delete:%d:%d", deleted.Version, s.clock().UTC().UnixNano()), map[string]any{"version": deleted.Version})
	})
	if errors.Is(err, sql.ErrNoRows) {
		return ErrAssignmentConflict
	}
	return err
}

func (s *ConfigAssignmentService) AdoptTeamDefault(ctx context.Context, userID, teamID string, version int64) (ConfigTeamDefaultAdoptionView, error) {
	if version < 1 {
		return ConfigTeamDefaultAdoptionView{}, ErrAssignmentForbidden
	}
	err := s.store.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		if err := teams.Lock(ctx, tx); err != nil {
			return err
		}
		if !teamMemberTx(ctx, tx, userID, teamID) {
			return ErrAssignmentForbidden
		}
		adoption, err := tx.Queries().AdoptTeamConfigDefault(ctx, dbsqlc.AdoptTeamConfigDefaultParams{AccountID: userID, TeamID: teamID, DefaultVersion: version})
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO control_config_assignments
 (id,machine_id,environment_id,repository_id,mode,consent_state,warning_revision,adopted_team_id,adopted_default_version)
SELECT 'cfgteam_' || substr(md5(m.id || $2),1,24), m.id, m.environment_id, $3, 'pull_only',
 CASE WHEN m.machine_kind='hosted' THEN 'not_required' ELSE 'pending' END,
 CASE WHEN m.machine_kind='hosted' THEN 'hosted' ELSE $4 END, $2, $5
FROM user_machines m WHERE m.user_id=$1 AND m.deleted_at IS NULL AND m.revoked_at IS NULL
ON CONFLICT (machine_id) DO UPDATE SET repository_id=EXCLUDED.repository_id,
 push_repository_id=NULL, mode='pull_only', adopted_team_id=EXCLUDED.adopted_team_id,
 adopted_default_version=EXCLUDED.adopted_default_version,
 warning_revision=EXCLUDED.warning_revision,
 consent_state=CASE WHEN control_config_assignments.consent_state='accepted'
   AND control_config_assignments.warning_revision=EXCLUDED.warning_revision
   THEN 'accepted' ELSE EXCLUDED.consent_state END,
 accepted_at=CASE WHEN control_config_assignments.consent_state='accepted'
   AND control_config_assignments.warning_revision=EXCLUDED.warning_revision
   THEN control_config_assignments.accepted_at ELSE NULL END,
 approved_pull_revision=NULL, approved_at=NULL, revoked_at=NULL,
 version=control_config_assignments.version+1, updated_at=now()
WHERE control_config_assignments.adopted_team_id IS NOT NULL OR control_config_assignments.revoked_at IS NOT NULL`,
			userID, teamID, adoption.RepositoryID, s.warningRevision, version)
		if err != nil {
			return err
		}
		return teams.AuditTx(ctx, tx, userID, teamID, "config_default_adopted", fmt.Sprintf("config-default-adopt:%d:%d", version, adoption.AdoptedAt.UnixNano()), map[string]any{"repository_id": adoption.RepositoryID, "version": version})
	})
	if errors.Is(err, sql.ErrNoRows) {
		return ConfigTeamDefaultAdoptionView{}, ErrAssignmentConflict
	}
	if err != nil {
		return ConfigTeamDefaultAdoptionView{}, err
	}
	return s.TeamDefaultAdoption(ctx, userID)
}

func (s *ConfigAssignmentService) TeamDefaultAdoption(ctx context.Context, userID string) (ConfigTeamDefaultAdoptionView, error) {
	item, err := s.store.Queries().GetTeamConfigDefaultAdoption(ctx, userID)
	if errors.Is(err, sql.ErrNoRows) {
		return ConfigTeamDefaultAdoptionView{}, ErrAssignmentForbidden
	}
	return ConfigTeamDefaultAdoptionView{ConfigTeamDefaultView: ConfigTeamDefaultView{
		TeamID: item.TeamID, Provider: item.Provider, ExternalRepositoryID: item.ExternalRepositoryID,
		DisplayName: item.DisplayName, Branch: item.Branch, Version: item.CurrentDefaultVersion,
	}, RepositoryID: item.RepositoryID, AdoptedVersion: item.DefaultVersion, UpdatePending: item.DefaultVersion != item.CurrentDefaultVersion}, err
}

func (s *ConfigAssignmentService) UnadoptTeamDefault(ctx context.Context, userID string) error {
	err := s.store.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		if err := teams.Lock(ctx, tx); err != nil {
			return err
		}
		current, err := tx.Queries().GetTeamConfigDefaultAdoption(ctx, userID)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrAssignmentForbidden
		}
		if err != nil {
			return err
		}
		if !teamMemberTx(ctx, tx, userID, current.TeamID) {
			return ErrAssignmentForbidden
		}
		if _, err := tx.Queries().RevokeAdoptedTeamConfigAssignments(ctx, dbsqlc.RevokeAdoptedTeamConfigAssignmentsParams{Now: sql.NullTime{Time: s.clock().UTC(), Valid: true}, AccountID: userID, TeamID: sql.NullString{String: current.TeamID, Valid: true}}); err != nil {
			return err
		}
		deleted, err := tx.Queries().DeleteTeamConfigDefaultAdoption(ctx, userID)
		if err != nil {
			return err
		}
		return teams.AuditTx(ctx, tx, userID, current.TeamID, "config_default_unadopted", fmt.Sprintf("config-default-unadopt:%d:%d", deleted.DefaultVersion, s.clock().UTC().UnixNano()), map[string]any{"repository_id": deleted.RepositoryID, "version": deleted.DefaultVersion})
	})
	if errors.Is(err, sql.ErrNoRows) {
		return ErrAssignmentForbidden
	}
	return err
}

func teamMemberTx(ctx context.Context, tx *db.Tx, userID, teamID string) bool {
	authority, err := tx.Queries().GetTeamConfigDefaultAuthority(ctx, dbsqlc.GetTeamConfigDefaultAuthorityParams{AccountID: userID, TeamID: teamID})
	return err == nil && (authority.OwnerAccount == userID || authority.Active.Valid && authority.Active.Bool)
}

func teamAdministratorTx(ctx context.Context, tx *db.Tx, userID, teamID string) bool {
	authority, err := tx.Queries().GetTeamConfigDefaultAuthority(ctx, dbsqlc.GetTeamConfigDefaultAuthorityParams{AccountID: userID, TeamID: teamID})
	return err == nil && (authority.OwnerAccount == userID || authority.Active.Valid && authority.Active.Bool && authority.Role.Valid && authority.Role.String == "admin")
}

func (s *ConfigAssignmentService) teamMember(ctx context.Context, userID, teamID string) bool {
	authority, err := s.store.Queries().GetTeamConfigDefaultAuthority(ctx, dbsqlc.GetTeamConfigDefaultAuthorityParams{AccountID: userID, TeamID: teamID})
	return err == nil && (authority.OwnerAccount == userID || authority.Active.Valid && authority.Active.Bool)
}

func (s *ConfigAssignmentService) teamAdministrator(ctx context.Context, userID, teamID string) bool {
	authority, err := s.store.Queries().GetTeamConfigDefaultAuthority(ctx, dbsqlc.GetTeamConfigDefaultAuthorityParams{AccountID: userID, TeamID: teamID})
	return err == nil && (authority.OwnerAccount == userID || authority.Active.Valid && authority.Active.Bool && authority.Role.Valid && authority.Role.String == "admin")
}

func teamDefaultView(item dbsqlc.TeamConfigDefault) ConfigTeamDefaultView {
	return ConfigTeamDefaultView{TeamID: item.TeamID, Provider: item.Provider, ExternalRepositoryID: item.ExternalRepositoryID, DisplayName: item.DisplayName, Branch: item.Branch, Version: item.Version}
}
