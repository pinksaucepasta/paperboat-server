package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/auth"
	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/teams"
	"github.com/pinksaucepasta/paperboat-server/internal/usermachines"
)

// Exercise production session/device authentication and HTTP authorization. Only
// the external identity provider is substituted, as in the existing auth suite.
func TestTeamMachineAuthenticatedHTTPLifecycle(t *testing.T) {
	dsn := os.Getenv("PAPERBOAT_TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL required")
	}
	if err := db.ValidateIsolatedTestDSN(dsn, os.Getenv("PAPERBOAT_DATABASE_DSN")); err != nil {
		t.Fatal(err)
	}
	store, err := db.Open(config.Database{Driver: "postgres", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := db.Migrate(context.Background(), store); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	writer := audit.NewWriter(store)
	authService := auth.NewService(store, writer, auth.FakeWorkOSVerifier{}, []string{"test-session-key"}, true, "https://login.pprbt.dev")
	device := auth.NewDeviceService(store, writer, cfg.CLIAuth, []string{"test-device-hash-key"})
	router := authTestOriginHandler{next: NewRouter(Options{Config: cfg, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Auth: authService, DeviceAuth: device, Teams: teams.NewService(store), Machines: usermachines.New(store, writer, usermachines.Policy{}, nil)})}
	suffix := fmt.Sprint(time.Now().UnixNano())
	ownerEmail, memberEmail := "team-owner-"+suffix+"@example.test", "team-member-"+suffix+"@example.test"
	ownerCookies := loginCookies(t, router, "workos_owner_"+suffix+":"+ownerEmail+":Owner")
	memberCookies := loginCookies(t, router, "workos_member_"+suffix+":"+memberEmail+":Member")
	owner, member := userIDByEmail(t, store, ownerEmail), userIDByEmail(t, store, memberEmail)
	ownerToken, memberToken := authorizeCLI(t, router, ownerCookies).AccessToken, authorizeCLI(t, router, memberCookies).AccessToken
	machine, teamID := "http_machine_"+suffix, "http_team_"+suffix
	if _, err := store.SQL().ExecContext(context.Background(), `INSERT INTO paperboat.user_machines(id,user_id,environment_id,display_name,platform,architecture,workspace_root,state,seat_state,online,configured_capabilities,observed_capabilities) VALUES($1,$2,$3,'HTTP host','linux','amd64','/workspace','online','occupied',true,ARRAY['terminal_host'],ARRAY['terminal_host'])`, machine, owner, "env_"+suffix); err != nil {
		t.Fatal(err)
	}
	call := func(token, method, path string, body any, status int, out any) {
		t.Helper()
		payload, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(method, path, bytes.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		// Single-machine reads are the dashboard's session-authenticated route;
		// team mutations above use the independently issued CLI bearer tokens.
		if method == http.MethodGet {
			req.Header.Del("Authorization")
			if token == ownerToken {
				addCookies(req, ownerCookies)
			} else if token == memberToken {
				addCookies(req, memberCookies)
			}
		}
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != status {
			t.Fatalf("%s %s: status %d want %d", method, path, rec.Code, status)
		}
		if out != nil {
			var envelope struct {
				Data json.RawMessage `json:"data"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(envelope.Data, out); err != nil {
				t.Fatal(err)
			}
		}
	}
	var team teams.Team
	call("", http.MethodPost, "/v1/teams", teams.CreateRequest{OperationID: "create", TeamID: teamID}, 401, nil)
	call(ownerToken, http.MethodPost, "/v1/teams", teams.CreateRequest{OperationID: "create", TeamID: teamID}, 200, &team)
	var invite teams.Invitation
	call(ownerToken, http.MethodPost, "/v1/teams/"+teamID+"/invitations", teams.InviteRequest{OperationID: "invite", ExpectedGeneration: team.Generation, AccountID: member}, 200, &invite)
	call(memberToken, http.MethodPost, "/v1/team-invitations/"+invite.InvitationID+"/accept", teams.AcceptRequest{OperationID: "accept"}, 200, &team)
	call(ownerToken, http.MethodPost, "/v1/teams/"+teamID+"/machines", teams.MachineRequest{OperationID: "share", ExpectedGeneration: team.Generation, MachineID: machine, Action: "share"}, 200, &team)
	call(memberToken, http.MethodGet, "/v1/machines/"+machine, nil, 404, nil)
	call(ownerToken, http.MethodPost, "/v1/teams/"+teamID+"/machine-grants", teams.MachineGrantRequest{OperationID: "grant", ExpectedGeneration: team.Generation, MachineID: machine, Audience: "selected_member", AccountID: member, Capabilities: []string{"terminal"}, Active: true}, 200, &team)
	var visible usermachines.UserMachine
	call(memberToken, http.MethodGet, "/v1/machines/"+machine, nil, 200, &visible)
	if visible.CanManage || len(visible.Permissions) != 1 || visible.Permissions[0] != "terminal" {
		t.Fatal("HTTP permissions do not match exact grant")
	}
	call(memberToken, http.MethodPost, "/v1/teams/"+teamID+"/machine-grants", teams.MachineGrantRequest{OperationID: "escalate", ExpectedGeneration: team.Generation, MachineID: machine, Audience: "all_members", Capabilities: []string{"exec"}, Active: true}, 403, nil)
	call(ownerToken, http.MethodPost, "/v1/teams/"+teamID+"/machines", teams.MachineRequest{OperationID: "unshare", ExpectedGeneration: team.Generation, MachineID: machine, Action: "unshare"}, 200, &team)
	call(memberToken, http.MethodGet, "/v1/machines/"+machine, nil, 404, nil)
	call(ownerToken, http.MethodGet, "/v1/machines/"+machine, nil, 200, &visible)
	if !visible.CanManage {
		t.Fatal("withdrawal removed owner control")
	}

	var activity teams.ActivityPage
	activityPath := "/v1/teams/" + teamID + "/activity?limit=2"
	call("", http.MethodGet, activityPath, nil, 401, nil)
	call(memberToken, http.MethodGet, activityPath, nil, 403, nil)
	call(ownerToken, http.MethodGet, activityPath, nil, 200, &activity)
	if len(activity.Items) != 2 || activity.NextCursor == "" {
		t.Fatal("activity pagination missing")
	}
	call(ownerToken, http.MethodPost, "/v1/teams/"+teamID+"/actions", teams.MutationRequest{OperationID: "appoint", ExpectedGeneration: team.Generation, Action: "role", AccountID: member, Role: "admin"}, 200, &team)
	call(memberToken, http.MethodGet, activityPath, nil, 200, &activity)
	call(memberToken, http.MethodPost, "/v1/teams/"+teamID+"/actions", teams.MutationRequest{OperationID: "admin_delete", ExpectedGeneration: team.Generation, Action: "delete", Confirmation: teamID}, 403, nil)
	call(ownerToken, http.MethodPost, "/v1/teams/"+teamID+"/actions", teams.MutationRequest{OperationID: "demote", ExpectedGeneration: team.Generation, Action: "role", AccountID: member, Role: "member"}, 200, &team)
	call(memberToken, http.MethodGet, activityPath+"&cursor="+activity.NextCursor, nil, 403, nil)
	call(ownerToken, http.MethodPost, "/v1/teams/"+teamID+"/actions", teams.MutationRequest{OperationID: "owner_leave", ExpectedGeneration: team.Generation, Action: "leave"}, 403, nil)
	call(ownerToken, http.MethodPost, "/v1/teams/"+teamID+"/actions", teams.MutationRequest{OperationID: "transfer", ExpectedGeneration: team.Generation, Action: "transfer", AccountID: member}, 200, &team)
	call(ownerToken, http.MethodGet, activityPath, nil, 403, nil)
	call(memberToken, http.MethodGet, activityPath, nil, 200, &activity)
	call(ownerToken, http.MethodPost, "/v1/teams/"+teamID+"/actions", teams.MutationRequest{OperationID: "leave", ExpectedGeneration: team.Generation, Action: "leave"}, 200, &team)
	call(memberToken, http.MethodPost, "/v1/teams/"+teamID+"/actions", teams.MutationRequest{OperationID: "delete", ExpectedGeneration: team.Generation, Action: "delete", Confirmation: teamID}, 200, &team)
	call(memberToken, http.MethodGet, activityPath, nil, 404, nil)
}
