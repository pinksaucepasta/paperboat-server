package teams

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
)

// Machine grants are typed details of the team's existing resource binding.
// Administrative roles govern mutations; they never imply use capabilities.
type MachineGrant struct {
	MachineID    string   `json:"machine_id"`
	Audience     string   `json:"audience"`
	AccountID    string   `json:"account_id,omitempty"`
	Capabilities []string `json:"capabilities"`
	Generation   uint64   `json:"generation"`
	Active       bool     `json:"active"`
}
type MachineBinding struct {
	MachineID              string   `json:"machine_id"`
	OwnerAccount           string   `json:"owner_account"`
	OwnerTeamID            string   `json:"owner_team_id,omitempty"`
	DisplayName            string   `json:"display_name"`
	State                  string   `json:"state"`
	Online                 bool     `json:"online"`
	ConfiguredCapabilities []string `json:"configured_capabilities"`
	Generation             uint64   `json:"generation"`
	Active                 bool     `json:"active"`
}
type MachineRequest struct {
	OperationID        string `json:"operation_id"`
	ExpectedGeneration uint64 `json:"expected_generation"`
	MachineID          string `json:"machine_id"`
	Action             string `json:"action"`
	Confirmation       string `json:"confirmation,omitempty"`
}
type MachineGrantRequest struct {
	OperationID        string   `json:"operation_id"`
	ExpectedGeneration uint64   `json:"expected_generation"`
	MachineID          string   `json:"machine_id"`
	Audience           string   `json:"audience"`
	AccountID          string   `json:"account_id,omitempty"`
	Capabilities       []string `json:"capabilities"`
	Active             bool     `json:"active"`
}

func ValidMachineCapability(capability string) bool {
	switch capability {
	case "terminal", "exec", "managed_ssh", "files", "preview_manage", "tunnel_manage":
		return true
	}
	return false
}
func validMachineGrant(r MachineGrantRequest) bool {
	if !validID(r.MachineID) || len(r.Capabilities) < 1 || len(r.Capabilities) > 6 {
		return false
	}
	if r.Audience != "all_members" && r.Audience != "selected_member" || r.Audience == "all_members" && r.AccountID != "" || r.Audience == "selected_member" && !validID(r.AccountID) {
		return false
	}
	seen := map[string]bool{}
	for _, c := range r.Capabilities {
		if !ValidMachineCapability(c) || seen[c] {
			return false
		}
		seen[c] = true
	}
	return true
}

// AuthorizeMachineTx requires Lock first and binds a decision to one ownership
// path. An empty team means personal ownership, never an arbitrary team fallback.
func AuthorizeMachineTx(ctx context.Context, tx *db.Tx, account, team, machine, capability string) (Decision, error) {
	d := Decision{AccountID: account, TeamID: team, ResourceKind: "machine", ResourceID: machine, Permission: capability}
	if !ValidMachineCapability(capability) || !validID(account) || !validID(machine) {
		return d, ErrInvalid
	}
	var allowed bool
	if team == "" {
		err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM user_machines WHERE id=$1 AND user_id=$2 AND owner_team_id IS NULL AND revoked_at IS NULL AND deleted_at IS NULL)`, machine, account).Scan(&allowed)
		if err != nil {
			return d, err
		}
		if !allowed {
			return d, ErrForbidden
		}
		return d, nil
	}
	err := tx.QueryRow(ctx, `SELECT team_machine_capability_allowed($1,$2,$3,$4)`, account, team, machine, capability).Scan(&allowed)
	if err != nil {
		return d, err
	}
	if !allowed {
		return d, ErrForbidden
	}
	err = tx.QueryRow(ctx, `SELECT t.generation,m.membership_generation,CASE WHEN t.owner_account=$1 THEN 'owner' ELSE m.role END,b.generation,max(g.generation) FROM teams t JOIN team_members m USING(team_id) JOIN team_resource_bindings b USING(team_id) JOIN team_machine_grants g ON g.team_id=b.team_id AND g.machine_id=b.resource_id WHERE t.team_id=$2 AND m.account_id=$1 AND b.resource_kind='machine' AND b.resource_id=$3 AND g.active AND (g.audience='all_members' OR g.account_id=$1) AND $4=ANY(g.capabilities) GROUP BY t.generation,m.membership_generation,t.owner_account,m.role,b.generation`, account, team, machine, capability).Scan(&d.TeamGeneration, &d.MembershipGeneration, &d.Role, &d.BindingGeneration, &d.GrantGeneration)
	return d, err
}

func (s *Service) GrantMachine(ctx context.Context, account, team string, r MachineGrantRequest) (Team, error) {
	if !validMachineGrant(r) {
		return Team{}, ErrInvalid
	}
	r.Capabilities = slices.Clone(r.Capabilities)
	slices.Sort(r.Capabilities)
	return s.mutate(ctx, account, team, r.OperationID, "machine_grant", r.ExpectedGeneration, r, func(ctx context.Context, tx *db.Tx, t Team, actor Member) error {
		owner, ownerTeam, err := machineOwnerTx(ctx, tx, r.MachineID)
		if err != nil {
			return err
		}
		if !administrative(actor.Role) && !(ownerTeam == "" && owner == account) {
			return ErrForbidden
		}
		if ownerTeam != "" && ownerTeam != team {
			return ErrForbidden
		}
		if r.Audience == "selected_member" {
			if _, ok := member(t, r.AccountID); !ok {
				return ErrForbidden
			}
		}
		var bound bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM team_resource_bindings WHERE team_id=$1 AND resource_kind='machine' AND resource_id=$2 AND active AND owner_account=$3)`, team, r.MachineID, owner).Scan(&bound); err != nil {
			return err
		}
		if !bound {
			return ErrForbidden
		}
		if r.Audience == "all_members" {
			_, err = tx.Exec(ctx, `INSERT INTO team_machine_grants(team_id,machine_id,audience,capabilities,active) VALUES($1,$2,'all_members',$3,$4) ON CONFLICT(team_id,machine_id) WHERE audience='all_members' DO UPDATE SET capabilities=EXCLUDED.capabilities,active=EXCLUDED.active,generation=team_machine_grants.generation+1`, team, r.MachineID, r.Capabilities, r.Active)
		} else {
			_, err = tx.Exec(ctx, `INSERT INTO team_machine_grants(team_id,machine_id,audience,account_id,capabilities,active) VALUES($1,$2,'selected_member',$3,$4,$5) ON CONFLICT(team_id,machine_id,account_id) WHERE audience='selected_member' DO UPDATE SET capabilities=EXCLUDED.capabilities,active=EXCLUDED.active,generation=team_machine_grants.generation+1`, team, r.MachineID, r.AccountID, r.Capabilities, r.Active)
		}
		return err
	})
}
func machineOwnerTx(ctx context.Context, tx *db.Tx, machine string) (string, string, error) {
	var owner, team string
	err := tx.QueryRow(ctx, `SELECT user_id,coalesce(owner_team_id,'') FROM user_machines WHERE id=$1 AND revoked_at IS NULL AND deleted_at IS NULL FOR UPDATE`, machine).Scan(&owner, &team)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return owner, team, err
}
func (s *Service) Machine(ctx context.Context, account, team string, r MachineRequest) (Team, error) {
	if !validID(r.MachineID) {
		return Team{}, ErrInvalid
	}
	return s.mutate(ctx, account, team, r.OperationID, "machine_"+r.Action, r.ExpectedGeneration, r, func(ctx context.Context, tx *db.Tx, t Team, actor Member) error {
		owner, ownerTeam, err := machineOwnerTx(ctx, tx, r.MachineID)
		if err != nil {
			return err
		}
		switch r.Action {
		case "share":
			if owner != account || ownerTeam != "" {
				return ErrForbidden
			}
			return bindMachineTx(ctx, tx, team, r.MachineID, owner)
		case "unshare":
			if ownerTeam != "" || owner != account && !administrative(actor.Role) {
				return ErrForbidden
			}
			return unbindMachineTx(ctx, tx, team, r.MachineID)
		case "transfer_to_team":
			if ownerTeam != "" || owner != account || !administrative(actor.Role) {
				return ErrForbidden
			}
			if r.Confirmation != r.MachineID {
				return ErrInvalid
			}
			var published bool
			if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM preview_leases WHERE owner_device_id=$1 AND access_mode='public' AND terminal_state='active') OR EXISTS(SELECT 1 FROM tunnels t WHERE t.access_mode='public' AND t.deleted_at IS NULL AND (t.created_by_host_id=$1 OR EXISTS(SELECT 1 FROM tunnel_connectors c WHERE c.tunnel_id=t.id AND c.host_id=$1 AND c.revoked_at IS NULL)))`, r.MachineID).Scan(&published); err != nil {
				return err
			}
			if published {
				return ErrMachinePublication
			}
			if err = bindMachineTx(ctx, tx, team, r.MachineID, owner); err != nil {
				return err
			}
			// Other personal shares cannot silently become grants over team property.
			if _, err = tx.Exec(ctx, `UPDATE teams SET generation=generation+1 WHERE team_id IN (SELECT team_id FROM team_resource_bindings WHERE resource_kind='machine' AND resource_id=$1 AND team_id<>$2 AND active)`, r.MachineID, team); err != nil {
				return err
			}
			if _, err = tx.Exec(ctx, `UPDATE team_resource_bindings SET active=false,generation=generation+1 WHERE resource_kind='machine' AND resource_id=$1 AND team_id<>$2 AND active`, r.MachineID, team); err != nil {
				return err
			}
			if _, err = tx.Exec(ctx, `UPDATE team_machine_grants SET active=false,generation=generation+1 WHERE machine_id=$1 AND team_id<>$2 AND active`, r.MachineID, team); err != nil {
				return err
			}
			_, err = tx.Exec(ctx, `UPDATE user_machines SET owner_team_id=$2,version=version+1,updated_at=now() WHERE id=$1`, r.MachineID, team)
			return err
		case "remove":
			if ownerTeam != team || !administrative(actor.Role) {
				return ErrForbidden
			}
			if r.Confirmation != r.MachineID {
				return ErrInvalid
			}
			if err = unbindMachineTx(ctx, tx, team, r.MachineID); err != nil {
				return err
			}
			return removeTeamMachineTx(ctx, tx, team, r.MachineID)
		default:
			return ErrInvalid
		}
	})
}
func bindMachineTx(ctx context.Context, tx *db.Tx, team, machine, owner string) error {
	var count int
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT count(*),coalesce(bool_or(resource_kind='machine' AND resource_id=$2),false) FROM team_resource_bindings WHERE team_id=$1`, team, machine).Scan(&count, &exists); err != nil {
		return err
	}
	if !exists && count >= MaximumResources {
		return ErrLimit
	}
	_, err := tx.Exec(ctx, `INSERT INTO team_resource_bindings(team_id,resource_kind,resource_id,owner_account,active,generation) VALUES($1,'machine',$2,$3,true,1) ON CONFLICT(team_id,resource_kind,resource_id) DO UPDATE SET active=true,generation=team_resource_bindings.generation+1`, team, machine, owner)
	return err
}
func unbindMachineTx(ctx context.Context, tx *db.Tx, team, machine string) error {
	if _, err := tx.Exec(ctx, `UPDATE team_resource_bindings SET active=false,generation=generation+1 WHERE team_id=$1 AND resource_kind='machine' AND resource_id=$2 AND active`, team, machine); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `UPDATE team_machine_grants SET active=false,generation=generation+1 WHERE team_id=$1 AND machine_id=$2 AND active`, team, machine)
	return err
}

func readMachinesTx(ctx context.Context, tx *db.Tx, team string, out *Team) error {
	out.Machines = []MachineBinding{}
	out.MachineGrants = []MachineGrant{}
	rows, err := tx.Query(ctx, `SELECT m.id,CASE WHEN m.owner_team_id IS NULL THEN m.user_id ELSE '' END,coalesce(m.owner_team_id,''),m.display_name,m.state,m.online,m.configured_capabilities,b.generation,b.active FROM team_resource_bindings b JOIN user_machines m ON m.id=b.resource_id WHERE b.team_id=$1 AND b.resource_kind='machine' ORDER BY m.id`, team)
	if err != nil {
		return err
	}
	for rows.Next() {
		var b MachineBinding
		if err = rows.Scan(&b.MachineID, &b.OwnerAccount, &b.OwnerTeamID, &b.DisplayName, &b.State, &b.Online, &b.ConfiguredCapabilities, &b.Generation, &b.Active); err != nil {
			rows.Close()
			return err
		}
		out.Machines = append(out.Machines, b)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	rows, err = tx.Query(ctx, `SELECT machine_id,audience,coalesce(account_id,''),capabilities,generation,active FROM team_machine_grants WHERE team_id=$1 ORDER BY machine_id,audience,account_id`, team)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var g MachineGrant
		if err = rows.Scan(&g.MachineID, &g.Audience, &g.AccountID, &g.Capabilities, &g.Generation, &g.Active); err != nil {
			return err
		}
		out.MachineGrants = append(out.MachineGrants, g)
	}
	return rows.Err()
}

// The same credential, ENV and runtime cleanup serves personal and team removal.
func removeTeamMachineTx(ctx context.Context, tx *db.Tx, team, machine string) error {
	var issuer, environment string
	if err := tx.QueryRow(ctx, `SELECT user_id,environment_id FROM user_machines WHERE id=$1 AND owner_team_id=$2 FOR UPDATE`, machine, team).Scan(&issuer, &environment); err != nil {
		return err
	}
	now := time.Now().UTC()
	if err := db.RequireVaultRotationTx(ctx, tx, issuer); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE user_machines SET revoked_at=coalesce(revoked_at,$3),state='revoked',seat_state='released',online=false,version=version+1,updated_at=$3 WHERE id=$1 AND owner_team_id=$2`, machine, team, now); err != nil {
		return err
	}
	if err := db.CleanupMachineDeviceTx(ctx, tx, issuer, machine, now); err != nil {
		return err
	}
	return db.RevokeMachineEnvironmentTx(ctx, tx, environment, now)
}
func removeTeamMachinesTx(ctx context.Context, tx *db.Tx, team string) error {
	rows, err := tx.Query(ctx, `SELECT id FROM user_machines WHERE owner_team_id=$1 AND revoked_at IS NULL AND deleted_at IS NULL ORDER BY id`, team)
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, id := range ids {
		if err = removeTeamMachineTx(ctx, tx, team, id); err != nil {
			return err
		}
	}
	return nil
}
