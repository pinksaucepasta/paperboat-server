package teams

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
)

type Service struct{ db *db.DB }

func NewService(store *db.DB) *Service { return &Service{db: store} }
func Lock(ctx context.Context, tx *db.Tx) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(160235)`)
	return err
}
func AuditTx(ctx context.Context, tx *db.Tx, account, team, action, operation string, metadata map[string]any) error {
	metadata, err := activityMetadata(metadata, true)
	if err != nil {
		return err
	}
	return audit.NewWriter(nil).WriteTx(ctx, tx, audit.Event{ActorUserID: account, ActorType: audit.ActorUser, EventType: "team." + action, ResourceType: "team", ResourceID: team, IdempotencyKey: account + ":" + operation, Metadata: metadata})
}
func ReadTx(ctx context.Context, tx *db.Tx, id string) (Team, error) {
	out := Team{TeamID: id, Members: []Member{}, Grants: []Grant{}}
	err := tx.QueryRow(ctx, `SELECT owner_account,generation,deleted_at IS NOT NULL,CASE WHEN deleted_at IS NOT NULL THEN 'deleted' ELSE coalesce((SELECT CASE WHEN rotation_required THEN 'rotation_pending' ELSE 'ready' END FROM environment_vault_teams WHERE team_id=$1),'not_initialized') END FROM teams WHERE team_id=$1 FOR UPDATE`, id).Scan(&out.OwnerAccount, &out.Generation, &out.Deleted, &out.ENVStatus)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, ErrNotFound
	}
	if err != nil {
		return out, err
	}
	rows, err := tx.Query(ctx, `SELECT account_id,membership_generation,CASE WHEN account_id=$2 THEN 'owner' ELSE role END,active FROM team_members WHERE team_id=$1 ORDER BY account_id`, id, out.OwnerAccount)
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var m Member
		if err = rows.Scan(&m.AccountID, &m.MembershipGeneration, &m.Role, &m.Active); err != nil {
			rows.Close()
			return out, err
		}
		out.Members = append(out.Members, m)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	rows, err = tx.Query(ctx, `SELECT account_id,resource_kind,resource_id,permission,generation,active FROM team_resource_grants WHERE team_id=$1 ORDER BY resource_kind,resource_id,account_id`, id)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var g Grant
		if err = rows.Scan(&g.AccountID, &g.ResourceKind, &g.ResourceID, &g.Permission, &g.Generation, &g.Active); err != nil {
			return out, err
		}
		out.Grants = append(out.Grants, g)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	rows, err = tx.Query(ctx, `SELECT terminal_session_id,audience,coalesce(account_id,''),role,generation,active FROM team_terminal_session_grants WHERE team_id=$1 ORDER BY terminal_session_id,audience,account_id`, id)
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var g TerminalSessionGrant
		if err = rows.Scan(&g.TerminalSessionID, &g.Audience, &g.AccountID, &g.Role, &g.Generation, &g.Active); err != nil {
			rows.Close()
			return out, err
		}
		out.TerminalSessionGrants = append(out.TerminalSessionGrants, g)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	err = readMachinesTx(ctx, tx, id, &out)
	return out, err
}

// AuthorizeTx requires Lock first. Decisions describe current authoritative state;
// consumers must revalidate generations before forwarding or using cached access.
func AuthorizeTx(ctx context.Context, tx *db.Tx, account, team, kind, id, permission string) (Decision, error) {
	if kind == "machine" {
		return AuthorizeMachineTx(ctx, tx, account, team, id, permission)
	}
	var d Decision
	t, err := ReadTx(ctx, tx, team)
	if err != nil {
		return d, err
	}
	m, ok := member(t, account)
	if t.Deleted || !ok {
		return d, ErrForbidden
	}
	d = Decision{TeamID: team, AccountID: account, Role: m.Role, TeamGeneration: t.Generation, MembershipGeneration: m.MembershipGeneration, ResourceKind: kind, ResourceID: id, Permission: permission}
	var active bool
	err = tx.QueryRow(ctx, `SELECT active,generation FROM team_resource_bindings WHERE team_id=$1 AND resource_kind=$2 AND resource_id=$3`, team, kind, id).Scan(&active, &d.BindingGeneration)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && !active {
		return d, ErrForbidden
	}
	if err != nil {
		return d, err
	}
	if kind == "preview" || kind == "tunnel" || kind == "lazy_policy" {
		var current bool
		query := `SELECT EXISTS(SELECT 1 FROM tunnels r JOIN team_resource_bindings b ON b.resource_id=r.id AND b.owner_account=r.account_id WHERE b.team_id=$1 AND b.resource_kind='tunnel' AND r.id=$2 AND r.deleted_at IS NULL)`
		if kind == "preview" {
			query = `SELECT EXISTS(SELECT 1 FROM preview_leases r JOIN team_resource_bindings b ON b.resource_id=r.id AND b.owner_account=r.account_id WHERE b.team_id=$1 AND b.resource_kind='preview' AND r.id=$2 AND r.terminal_state='active' AND r.lease_deadline>now())`
		}
		if kind == "lazy_policy" {
			query = `SELECT EXISTS(SELECT 1 FROM lazy_access_policies r JOIN team_resource_bindings b ON b.resource_id=r.id AND b.owner_account=r.account_id WHERE b.team_id=$1 AND b.resource_kind='lazy_policy' AND r.id=$2 AND r.deleted_at IS NULL AND r.expires_at>now())`
		}
		if err = tx.QueryRow(ctx, query, team, id).Scan(&current); err != nil {
			return d, err
		}
		if !current {
			return d, ErrForbidden
		}
	}
	for _, g := range t.Grants {
		if g.AccountID == account && g.ResourceKind == kind && g.ResourceID == id && g.Active && permits(kind, g.Permission, permission) {
			d.GrantGeneration = g.Generation
			return d, nil
		}
	}
	return d, ErrForbidden
}
func (s *Service) Authorize(ctx context.Context, account, team, kind, id, permission string) (Decision, error) {
	var out Decision
	err := s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		if err := Lock(ctx, tx); err != nil {
			return err
		}
		var err error
		out, err = AuthorizeTx(ctx, tx, account, team, kind, id, permission)
		return err
	})
	return out, err
}
func FenceENVTx(ctx context.Context, tx *db.Tx, team string) error {
	_, err := tx.Exec(ctx, `UPDATE environment_vault_teams SET rotation_required=true WHERE team_id=$1`, team)
	if err != nil {
		return err
	}
	return InvalidateENVTx(ctx, tx, team)
}
func InvalidateENVTx(ctx context.Context, tx *db.Tx, team string) error {
	_, err := tx.Exec(ctx, `INSERT INTO environment_vault_projection_fences(machine_id,generation) SELECT DISTINCT machine_id,1 FROM environment_vault_projection_sources WHERE owner_kind='team' AND owner_id=$1 ON CONFLICT(machine_id) DO UPDATE SET generation=environment_vault_projection_fences.generation+1`, team)
	return err
}

// RemoveMemberTx revokes immediately, without requiring keys to finish rekey.
// The caller authorizes the target and advances the team's generation atomically.
func RemoveMemberTx(ctx context.Context, tx *db.Tx, team, account string) error {
	var held bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM environment_vault_team_members WHERE team_id=$1 AND account_id=$2 AND grant_epoch>0)`, team, account).Scan(&held); err != nil {
		return err
	}
	for _, q := range []string{`UPDATE team_resource_bindings SET active=false,generation=generation+1 WHERE team_id=$1 AND resource_kind='terminal_session' AND owner_account=$2 AND active`, `UPDATE team_terminal_session_grants SET active=false,generation=generation+1 WHERE team_id=$1 AND account_id=$2 AND active`, `UPDATE team_machine_grants SET active=false,generation=generation+1 WHERE team_id=$1 AND account_id=$2 AND active`, `UPDATE team_resource_bindings b SET active=false,generation=b.generation+1 FROM user_machines m WHERE b.team_id=$1 AND b.resource_kind='machine' AND b.resource_id=m.id AND m.user_id=$2 AND m.owner_team_id IS NULL AND b.active`, `UPDATE team_machine_grants g SET active=false,generation=g.generation+1 FROM user_machines m WHERE g.team_id=$1 AND g.machine_id=m.id AND m.user_id=$2 AND m.owner_team_id IS NULL AND g.active`, `UPDATE team_members SET active=false,membership_generation=membership_generation+1 WHERE team_id=$1 AND account_id=$2 AND active`, `UPDATE team_resource_grants SET active=false,generation=generation+1 WHERE team_id=$1 AND account_id=$2 AND active`, `UPDATE environment_vault_team_members SET grant_epoch=0 WHERE team_id=$1 AND account_id=$2`, `DELETE FROM environment_vault_team_grants WHERE team_id=$1 AND account_id=$2`, `UPDATE team_invitations SET cancelled_at=now() WHERE team_id=$1 AND (recipient_account=$2 OR created_by=$2) AND accepted_at IS NULL AND cancelled_at IS NULL`} {
		if _, err := tx.Exec(ctx, q, team, account); err != nil {
			return err
		}
	}
	if err := revokeDepartingResourcesTx(ctx, tx, team, account); err != nil {
		return err
	}

	if held {
		return FenceENVTx(ctx, tx, team)
	}
	return InvalidateENVTx(ctx, tx, team)
}
func replay(ctx context.Context, tx *db.Tx, account, op, kind string, request, out any) (bool, []byte, error) {
	if !validID(account) || !validID(op) {
		return false, nil, ErrInvalid
	}
	raw, err := json.Marshal([]any{kind, request})
	if err != nil {
		return false, nil, err
	}
	hash := sha256.Sum256(raw)
	var digest, data []byte
	err = tx.QueryRow(ctx, `SELECT request_digest,result FROM team_operations WHERE account_id=$1 AND operation_id=$2`, account, op).Scan(&digest, &data)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, hash[:], nil
	}
	if err != nil {
		return false, nil, err
	}
	if !bytes.Equal(hash[:], digest) {
		return false, nil, ErrConflict
	}
	if err = json.Unmarshal(data, out); err != nil {
		return false, nil, err
	}
	return true, hash[:], nil
}
func save(ctx context.Context, tx *db.Tx, account, op string, digest []byte, out any) error {
	// Store a bounded receipt; retries read current authorized membership/grants.
	if t, ok := out.(Team); ok {
		t.Members = []Member{}
		t.Grants = []Grant{}
		t.Machines = []MachineBinding{}
		t.MachineGrants = []MachineGrant{}
		t.TerminalSessionGrants = []TerminalSessionGrant{}
		out = t
	}
	raw, err := json.Marshal(out)
	if err != nil {
		return err
	}
	if len(raw) > MaximumReceiptBytes {
		return ErrLimit
	}
	if _, err = tx.Exec(ctx, `INSERT INTO team_operations(account_id,operation_id,request_digest,result,created_at) VALUES($1,$2,$3,$4,clock_timestamp())`, account, op, digest, raw); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `DELETE FROM team_operations WHERE account_id=$1 AND operation_id IN(SELECT operation_id FROM team_operations WHERE account_id=$1 ORDER BY created_at DESC,operation_id DESC OFFSET $2)`, account, MaximumOperationReceipts); err != nil {
		return err
	}
	team := ""
	switch v := out.(type) {
	case Team:
		team = v.TeamID
	case Invitation:
		team = v.TeamID
	}
	if team != "" {
		return pruneInvitationsTx(ctx, tx, team)
	}
	return nil
}
func advance(ctx context.Context, tx *db.Tx, team string) error {
	_, err := tx.Exec(ctx, `UPDATE teams SET generation=generation+1 WHERE team_id=$1`, team)
	return err
}
func check(t Team, account string, expected uint64) (Member, error) {
	m, ok := member(t, account)
	if t.Deleted || !ok {
		return m, ErrForbidden
	}
	if expected != t.Generation || expected == 0 || expected >= MaximumCounter {
		return m, ErrConflict
	}
	return m, nil
}
func (s *Service) Get(ctx context.Context, account, team string) (Team, error) {
	var out Team
	err := s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		if err := Lock(ctx, tx); err != nil {
			return err
		}
		var err error
		out, err = ReadTx(ctx, tx, team)
		if err != nil {
			return err
		}
		if _, ok := member(out, account); !ok || out.Deleted {
			return ErrForbidden
		}
		return nil
	})
	return out, err
}
func (s *Service) List(ctx context.Context, account string) ([]Team, error) {
	out := []Team{}
	err := s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		out = []Team{}
		if err := Lock(ctx, tx); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT t.team_id FROM teams t JOIN team_members m USING(team_id) WHERE m.account_id=$1 AND m.active AND t.deleted_at IS NULL ORDER BY t.team_id LIMIT 129`, account)
		if err != nil {
			return err
		}
		ids := []string{}
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
		if len(ids) > MaximumMembers {
			return ErrLimit
		}
		for _, id := range ids {
			t, err := ReadTx(ctx, tx, id)
			if err != nil {
				return err
			}
			out = append(out, t)
		}
		return nil
	})
	return out, err
}

func pruneInvitationsTx(ctx context.Context, tx *db.Tx, team string) error {
	_, err := tx.Exec(ctx, `DELETE FROM team_invitations WHERE team_id=$1 AND invitation_id IN(SELECT invitation_id FROM team_invitations WHERE team_id=$1 AND (accepted_at IS NOT NULL OR cancelled_at IS NOT NULL) ORDER BY COALESCE(accepted_at,cancelled_at) DESC,invitation_id DESC OFFSET $2)`, team, MaximumInvitationHistory)
	return err
}
