package usermachines

import (
	"context"
	"database/sql"
	"errors"
	"github.com/pinksaucepasta/paperboat-server/internal/helperruntime"
	"github.com/pinksaucepasta/paperboat-server/internal/mint"
	"github.com/pinksaucepasta/paperboat-server/internal/teams"
	"time"
)

const terminalRecentOutputWarning = "Attaching includes up to 64 KiB of recent output, which may contain secrets regardless of ENV permissions."
const maximumTerminalCatalog = 512

type SharedTerminalTarget struct {
	Kind              string `json:"kind"`
	ID                string `json:"id"`
	Name              string `json:"name"`
	MachineID         string `json:"machine_id"`
	MachineGeneration int64  `json:"machine_generation"`
	Status            string `json:"status"`
	Reason            string `json:"reason"`
	EnvironmentID     string `json:"-"`
}
type SharedTerminalGrant struct {
	Audience   string `json:"audience"`
	AccountID  string `json:"account_id,omitempty"`
	Role       string `json:"role"`
	Active     bool   `json:"active"`
	Generation uint64 `json:"generation"`
}
type SharedTerminalSharing struct {
	Generation          uint64                `json:"generation"`
	TeamID              string                `json:"team_id"`
	Audience            string                `json:"audience"`
	Grants              []SharedTerminalGrant `json:"grants"`
	RecentOutputWarning string                `json:"recent_output_warning"`
}
type SharedTerminalSession struct {
	ID                    string                      `json:"id"`
	Name                  string                      `json:"name"`
	Target                SharedTerminalTarget        `json:"target"`
	OwnerAccount          string                      `json:"owner_account"`
	CanManage             bool                        `json:"can_manage"`
	Role                  string                      `json:"role"`
	Sharing               SharedTerminalSharing       `json:"sharing"`
	Participants          []helperruntime.Participant `json:"participants"`
	ParticipantsAvailable bool                        `json:"participants_available"`
	RuntimeGeneration     uint64                      `json:"-"`
}

func (s *Service) TerminalSessionCatalog(ctx context.Context, account string) ([]SharedTerminalSession, error) {
	return s.terminalSessionCatalog(ctx, account, "")
}
func (s *Service) terminalSessionCatalog(ctx context.Context, account, exactSession string) ([]SharedTerminalSession, error) {
	rows, err := s.db.SQL().QueryContext(ctx, `WITH sessions AS (
 SELECT s.id,s.name,s.owner_account,'machine'::text kind,m.id target_id,m.display_name target_name,m.id machine_id,m.environment_id,m.installation_generation,m.state,m.online,m.configured_capabilities @> ARRAY['terminal_host'] AND m.observed_capabilities @> ARRAY['terminal_host'] terminal_ready FROM user_machine_terminal_sessions s JOIN user_machines m ON m.id=s.user_machine_id WHERE s.deleted_at IS NULL AND m.deleted_at IS NULL
 UNION ALL SELECT s.id,s.name,s.owner_account,'hosted',p.id,p.name,m.id,m.environment_id,m.installation_generation,m.state,m.online,m.configured_capabilities @> ARRAY['terminal_host'] AND m.observed_capabilities @> ARRAY['terminal_host'] FROM project_terminal_sessions s JOIN projects p ON p.id=s.project_id JOIN LATERAL(SELECT * FROM user_machines WHERE environment_id=p.id AND deleted_at IS NULL ORDER BY created_at DESC LIMIT 1)m ON true WHERE s.deleted_at IS NULL)
	 SELECT x.id,x.name,x.owner_account,x.kind,x.target_id,x.target_name,x.machine_id,x.environment_id,x.installation_generation,x.state,x.online,x.terminal_ready,coalesce(b.team_id,''),coalesce(t.generation,0),coalesce(terminal_session_role($1,x.id),''),x.owner_account=$1,EXISTS(SELECT 1 FROM team_terminal_session_grants ag WHERE ag.team_id=b.team_id AND ag.terminal_session_id=x.id AND ag.audience='all_members' AND ag.active)
	 FROM sessions x LEFT JOIN team_resource_bindings b ON b.resource_kind='terminal_session' AND b.resource_id=x.id AND b.active LEFT JOIN teams t ON t.team_id=b.team_id AND t.deleted_at IS NULL
 WHERE ($2='' OR x.id=$2) AND (x.owner_account=$1 OR terminal_session_role($1,x.id) IN ('viewer','interactive')) ORDER BY x.name,x.id LIMIT 513`, account, exactSession)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SharedTerminalSession{}
	for rows.Next() {
		if len(out) >= maximumTerminalCatalog {
			return nil, ErrTerminalSessionLimit
		}
		var v SharedTerminalSession
		var state, role string
		var online bool
		var allMembers bool
		var observedTerminal bool
		if err = rows.Scan(&v.ID, &v.Name, &v.OwnerAccount, &v.Target.Kind, &v.Target.ID, &v.Target.Name, &v.Target.MachineID, &v.Target.EnvironmentID, &v.Target.MachineGeneration, &state, &online, &observedTerminal, &v.Sharing.TeamID, &v.Sharing.Generation, &role, &v.CanManage, &allMembers); err != nil {
			return nil, err
		}
		v.Role = role
		if v.CanManage {
			v.Role = "owner"
		}
		v.Target.Status, v.Target.Reason = "offline", "terminal_host_unavailable"
		if online && observedTerminal {
			v.Target.Status, v.Target.Reason = "ready", "ready"
		}
		v.Sharing.RecentOutputWarning = terminalRecentOutputWarning
		v.Sharing.Grants = []SharedTerminalGrant{}
		v.Participants = []helperruntime.Participant{}
		if v.Sharing.TeamID == "" {
			v.Sharing.Audience = "none"
		} else if allMembers {
			v.Sharing.Audience = "all_members"
		} else {
			v.Sharing.Audience = "selected_members"
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
func (s *Service) TerminalSessionSharing(ctx context.Context, account, sessionID string) (SharedTerminalSession, error) {
	items, err := s.terminalSessionCatalog(ctx, account, sessionID)
	if err != nil {
		return SharedTerminalSession{}, err
	}
	var item SharedTerminalSession
	found := false
	for _, v := range items {
		if v.ID == sessionID {
			item = v
			found = true
			break
		}
	}
	if !found {
		return item, ErrTerminalSessionNotFound
	}
	rows, err := s.db.SQL().QueryContext(ctx, `SELECT audience,coalesce(account_id,''),role,active,generation FROM team_terminal_session_grants WHERE team_id=$1 AND terminal_session_id=$2 ORDER BY audience,account_id`, item.Sharing.TeamID, sessionID)
	if err != nil {
		return item, err
	}
	defer rows.Close()
	all := false
	for rows.Next() {
		var g SharedTerminalGrant
		if err = rows.Scan(&g.Audience, &g.AccountID, &g.Role, &g.Active, &g.Generation); err != nil {
			return item, err
		}
		if item.CanManage || g.Audience == "all_members" || g.AccountID == account {
			item.Sharing.Grants = append(item.Sharing.Grants, g)
		}
		if g.Audience == "all_members" && g.Active {
			all = true
		}
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return item, err
	}
	rows.Close()
	if all {
		item.Sharing.Audience = "all_members"
	}
	if item.Target.Status != "ready" || s.controlSigner == nil {
		return item, nil
	}
	route, err := s.db.Queries().GetActiveHelperRouteForEnvironment(ctx, item.Target.EnvironmentID)
	if err != nil {
		return item, nil
	}
	now := s.now().UTC()
	token, err := s.controlSigner.SignCredential(mint.CredentialInput{Issuer: s.issuer, Audience: "paperboat-machine", Subject: item.OwnerAccount, JTI: newID("jti_terminal_snapshot"), IssuedAt: now, ExpiresAt: now.Add(time.Minute), CredentialClass: "terminal_operation", Scopes: []string{"terminal:operate"}, EnvironmentID: item.Target.EnvironmentID, MachineID: item.Target.MachineID, UserID: item.OwnerAccount, CLIClientSessionID: "control-plane", SessionID: item.ID})
	if err != nil {
		return item, nil
	}
	snap, err := s.controlRuntime.Terminal(ctx, "https://"+route.PublicHost, token, "snapshot", item.ID, newID("op_terminal_snapshot"))
	if err != nil {
		return item, nil
	}
	if _, err = s.db.SQL().ExecContext(ctx, `WITH project_updated AS (UPDATE project_terminal_sessions SET runtime_state=$2,launch_cwd=coalesce(nullif($3,''),launch_cwd),last_runtime_sync_at=now(),last_runtime_sequence=$4,updated_at=now() WHERE id=$1 RETURNING id) UPDATE user_machine_terminal_sessions SET runtime_state=$2,launch_cwd=coalesce(nullif($3,''),launch_cwd),last_runtime_sync_at=now(),last_runtime_sequence=$4,updated_at=now() WHERE id=$1`, item.ID, snap.State, snap.CWD, int64(snap.LatestSequence)); err != nil {
		return item, err
	}
	item.Participants = snap.Participants
	if item.Participants == nil {
		item.Participants = []helperruntime.Participant{}
	}
	item.ParticipantsAvailable = true
	item.RuntimeGeneration = snap.Generation
	if snap.State == "closed" || snap.State == "exited" || snap.State == "deleted" {
		item.Sharing = SharedTerminalSharing{Audience: "none", Grants: []SharedTerminalGrant{}, RecentOutputWarning: terminalRecentOutputWarning}
		item.Participants = []helperruntime.Participant{}
	}
	return item, nil
}

func (s *Service) GrantTerminalSessionSharing(ctx context.Context, account, teamID, sessionID string, in teams.TerminalSessionGrantRequest) (SharedTerminalSession, error) {
	current, err := s.TerminalSessionSharing(ctx, account, sessionID)
	if err != nil || !current.CanManage || !current.ParticipantsAvailable || current.RuntimeGeneration < 1 {
		if err != nil {
			return SharedTerminalSession{}, err
		}
		return SharedTerminalSession{}, ErrTerminalSessionNotFound
	}
	in.TerminalSessionID = sessionID
	in.RuntimeGeneration = current.RuntimeGeneration
	if _, err := teams.NewService(s.db).GrantTerminalSession(ctx, account, teamID, in); err != nil {
		return SharedTerminalSession{}, err
	}
	return s.TerminalSessionSharing(ctx, account, sessionID)
}
func (s *Service) EndTerminalSessionSharing(ctx context.Context, account, sessionID, operation string, expected uint64) (SharedTerminalSession, error) {
	var team string
	if err := s.db.SQL().QueryRowContext(ctx, `SELECT team_id FROM team_resource_bindings WHERE resource_kind='terminal_session' AND resource_id=$1 AND owner_account=$2 ORDER BY active DESC LIMIT 1`, sessionID, account).Scan(&team); errors.Is(err, sql.ErrNoRows) {
		return SharedTerminalSession{}, ErrTerminalSessionNotFound
	} else if err != nil {
		return SharedTerminalSession{}, err
	}
	if _, err := teams.NewService(s.db).EndTerminalSessionSharing(ctx, account, team, sessionID, operation, expected); err != nil {
		return SharedTerminalSession{}, err
	}
	return s.TerminalSessionSharing(ctx, account, sessionID)
}
func (s *Service) RemoveTerminalParticipant(ctx context.Context, account, sessionID, target, operation string, expected uint64) (SharedTerminalSession, error) {
	var team string
	if err := s.db.SQL().QueryRowContext(ctx, `SELECT team_id FROM team_resource_bindings WHERE resource_kind='terminal_session' AND resource_id=$1 AND active AND owner_account=$2`, sessionID, account).Scan(&team); err != nil {
		return SharedTerminalSession{}, ErrTerminalSessionNotFound
	}
	if _, err := teams.NewService(s.db).RemoveTerminalParticipant(ctx, account, team, sessionID, target, operation, expected); err != nil {
		return SharedTerminalSession{}, err
	}
	return s.TerminalSessionSharing(ctx, account, sessionID)
}
