package usermachines

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"

	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
	"github.com/pinksaucepasta/paperboat-server/internal/teams"
)

func (s *Service) describeMachineAccess(ctx context.Context, account string, machines ...*UserMachine) error {
	if len(machines) == 0 {
		return nil
	}
	ids := make([]string, 0, len(machines))
	byID := make(map[string]*UserMachine, len(machines))
	for _, machine := range machines {
		ids = append(ids, machine.ID)
		byID[machine.ID] = machine
	}
	rows, err := s.db.SQL().QueryContext(ctx, `SELECT m.id,machine_management_allowed($1,m.id), EXISTS(SELECT 1 FROM team_resource_bindings WHERE resource_kind='machine' AND resource_id=m.id AND active),coalesce((SELECT json_agg(capability) FROM unnest(ARRAY['terminal','exec','managed_ssh','files','preview_manage','tunnel_manage']) capability WHERE machine_capability_allowed($1,m.id,capability)),'[]'::json) FROM user_machines m WHERE m.id=ANY($2::text[])`, account, ids)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var manage, shared bool
		var permissions []byte
		if err := rows.Scan(&id, &manage, &shared, &permissions); err != nil {
			return err
		}
		machine := byID[id]
		machine.CanManage, machine.Shared = manage, shared
		if err := json.Unmarshal(permissions, &machine.Permissions); err != nil {
			return err
		}
	}
	return rows.Err()
}

// Persist authority under the same lock as team mutations. A permission withdrawn
// while a descriptor is prepared must never escape as an active access session.
func (s *Service) createAccessSession(ctx context.Context, in dbsqlc.CreateUserMachineAccessSessionParams) error {
	return s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		if err := teams.Lock(ctx, tx); err != nil {
			return err
		}
		if len(in.Capabilities) == 0 {
			return ErrMachineCapabilityUnavailable
		}
		machine, err := tx.Queries().GetUserMachineForCapability(ctx, dbsqlc.GetUserMachineForCapabilityParams{ID: in.UserMachineID, UserID: in.UserID, Capability: in.Capabilities[0]})
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if machine.State != "online" || !machine.Online {
			return ErrMachineOffline
		}
		for _, capability := range in.Capabilities {
			incoming := ""
			switch capability {
			case "terminal", "exec":
				incoming = "terminal_host"
			case "managed_ssh":
				incoming = "ssh_host"
			case "files":
				incoming = "file_receive"
			}
			if incoming != "" && (!slices.Contains(machine.ConfiguredCapabilities, incoming) || !slices.Contains(machine.ObservedCapabilities, incoming)) {
				return ErrMachineCapabilityUnavailable
			}
		}
		var personal bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM user_machines WHERE id=$1 AND user_id=$2 AND owner_team_id IS NULL AND revoked_at IS NULL AND deleted_at IS NULL)`, in.UserMachineID, in.UserID).Scan(&personal); err != nil {
			return err
		}
		if !personal {
			var team string
			err := tx.QueryRow(ctx, `SELECT b.team_id FROM team_resource_bindings b WHERE b.resource_kind='machine' AND b.resource_id=$1 AND NOT EXISTS(SELECT 1 FROM unnest($3::text[]) capability WHERE NOT team_machine_capability_allowed($2,b.team_id,$1,capability)) ORDER BY b.team_id LIMIT 1`, in.UserMachineID, in.UserID, in.Capabilities).Scan(&team)
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			}
			if err != nil {
				return err
			}
			in.TeamID = sql.NullString{String: team, Valid: true}
		}
		return tx.Queries().CreateUserMachineAccessSession(ctx, in)
	})
}
