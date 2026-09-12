package httpapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/accessdescriptor"
	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/auth"
	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/controlplane"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/metering"
	"github.com/pinksaucepasta/paperboat-server/internal/mint"
	"github.com/pinksaucepasta/paperboat-server/internal/teaminbox"
	"github.com/pinksaucepasta/paperboat-server/internal/teams"
	"github.com/pinksaucepasta/paperboat-server/internal/usermachines"
)

// This opt-in connected gate uses one isolated database, authenticated accounts,
// production sharing/Inbox/config/lifecycle services and a separately built real
// runtime. The account identity provider is a fixture; repository discovery and
// config Git operations use the explicitly authorized private GitHub fixture.
// This test does not claim fresh transport qualification.
func TestTask44ConnectedCollaboration(t *testing.T) {
	binary := os.Getenv("PAPERBOAT_TASK44_RUNTIME_BIN")
	if binary == "" {
		t.Skip("requires Task44 runtime test executable and isolated PostgreSQL")
	}
	dsn := os.Getenv("PAPERBOAT_TEST_DATABASE_DSN")
	if err := db.ValidateIsolatedTestDSN(dsn, os.Getenv("PAPERBOAT_DATABASE_DSN")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	store, err := db.Open(config.Database{Driver: "postgres", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err = db.Migrate(ctx, store); err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	write := func(name string, value any) {
		t.Helper()
		raw, e := json.Marshal(value)
		if e != nil {
			t.Fatal(e)
		}
		defer clear(raw)
		if e = os.WriteFile(filepath.Join(directory, name+".tmp"), raw, 0600); e != nil {
			t.Fatal(e)
		}
		if e = os.Rename(filepath.Join(directory, name+".tmp"), filepath.Join(directory, name)); e != nil {
			t.Fatal(e)
		}
	}
	waitJSON := func(name string, out any) {
		t.Helper()
		tick := time.NewTicker(25 * time.Millisecond)
		defer tick.Stop()
		deadline := time.NewTimer(40 * time.Second)
		defer deadline.Stop()
		for {
			raw, e := os.ReadFile(filepath.Join(directory, name))
			if e == nil {
				defer clear(raw)
				if json.Unmarshal(raw, out) != nil {
					t.Fatal("invalid runtime coordination")
				}
				return
			}
			if !os.IsNotExist(e) {
				t.Fatal(e)
			}
			select {
			case <-ctx.Done():
				t.Fatal("connected scenario deadline")
			case <-deadline.C:
				t.Fatal("runtime coordination deadline: " + name)
			case <-tick.C:
			}
		}
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := mint.New([]mint.Key{{ID: "task44", PrivateKey: private}}, "task44", mint.MaxProofTTL)
	if err != nil {
		t.Fatal(err)
	}
	writer := audit.NewWriter(store)
	cfg := config.Default()
	accounts := auth.NewService(store, writer, auth.FakeWorkOSVerifier{}, []string{"task44-isolated-session-key"}, true, "https://login.pprbt.dev")
	devices := auth.NewDeviceService(store, writer, cfg.CLIAuth, []string{"task44-isolated-device-key"})
	authority := teams.NewService(store)
	machines := usermachines.New(store, writer, usermachines.Policy{}, nil)
	machines.ConfigureAccess(nil, "https://task44.invalid", 5*time.Minute)
	machines.ConfigureTerminalSessions(4, signer, nil)
	machines.ConfigureFileTransfer(accessdescriptor.FileTransferPolicy{Revision: "task44", MaxFileBytes: 1 << 20, MaxBatchFiles: 2, MaxBatchBytes: 2 << 20, MaxConcurrentTransfers: 2, RetentionSeconds: 60, DeliveryTimeoutSeconds: 60, MaxPendingSpoolBytes: 2 << 20})
	inbox, err := teaminbox.New(store)
	if err != nil {
		t.Fatal(err)
	}
	machines.ConfigureTeamInbox(inbox)
	configs := controlplane.NewConfigAssignmentService(store, writer, "task44")

	router := authTestOriginHandler{next: NewRouter(Options{Config: cfg, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Auth: accounts, DeviceAuth: devices, Teams: authority, Machines: machines, TeamInbox: inbox, ConfigAssignments: configs})}
	suffix := fmt.Sprint(time.Now().UnixNano())
	type actor struct {
		id, token, cli string
		cookies        []*http.Cookie
	}
	login := func(name string) actor {
		email := "task44-" + name + suffix + "@invalid.test"
		cookies := loginCookies(t, router, "task44_"+name+suffix+":"+email+":"+name)
		out := actor{id: userIDByEmail(t, store, email), token: authorizeCLI(t, router, cookies).AccessToken, cookies: cookies}
		if err := store.SQL().QueryRowContext(ctx, `SELECT id FROM paperboat.cli_client_sessions WHERE user_id=$1 AND state='active'`, out.id).Scan(&out.cli); err != nil {
			t.Fatal(err)
		}
		return out
	}
	owner, member, outsider := login("owner"), login("member"), login("outsider")
	configProvider := task44ConfigProvider(t, ctx, store, cfg, configs, owner.id, member.id)
	teamID, otherTeam, machine, source, terminal, environment, edge := "t44_team_"+suffix, "t44_other_"+suffix, "t44_host_"+suffix, "t44_source_"+suffix, "t44_terminal_"+suffix, "t44_env_"+suffix, "t44_edge_"+suffix
	sql := func(query string, args ...any) {
		t.Helper()
		if _, e := store.SQL().ExecContext(ctx, query, args...); e != nil {
			t.Fatal(e)
		}
	}
	// Rows representing infrastructure discovery are bounded fixtures. All grants,
	// sharing, approval, adoption and departure below use their owning services.
	sql(`INSERT INTO paperboat.control_environments(id,workspace_id,owner_user_id) VALUES($1,$1,$2)`, environment, owner.id)
	sql(`INSERT INTO paperboat.control_environments(id,workspace_id,owner_user_id) VALUES($1,$1,$2)`, "env_"+source, member.id)
	sql(`INSERT INTO paperboat.user_machines(id,user_id,environment_id,display_name,platform,architecture,workspace_root,state,seat_state,online,installation_generation,configured_capabilities,observed_capabilities) VALUES($1,$2,$3,'Task44 host','linux','amd64','/workspace','online','occupied',true,1,ARRAY['terminal_host','file_receive'],ARRAY['terminal_host','file_receive'])`, machine, owner.id, environment)
	sql(`INSERT INTO paperboat.user_machines(id,user_id,environment_id,display_name,platform,architecture,workspace_root,state,seat_state,online,installation_generation) VALUES($1,$2,$3,'Task44 member','linux','amd64','/workspace','online','occupied',true,1)`, source, member.id, "env_"+source)
	sql(`INSERT INTO paperboat.user_machine_terminal_sessions(id,user_machine_id,terminal_id,name,owner_account,launch_cwd,runtime_state) VALUES($1,$2,$1,'task44-shared',$3,'/workspace','running')`, terminal, machine, owner.id)
	call := func(who actor, method, path string, body, out any, want int) {
		t.Helper()
		raw, e := json.Marshal(body)
		if e != nil {
			t.Fatal(e)
		}
		r := httptest.NewRequest(method, path, bytes.NewReader(raw))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer "+who.token)
		addCookies(r, who.cookies)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, r)
		if rec.Code != want {
			t.Fatalf("%s %s: status %d want %d", method, path, rec.Code, want)
		}
		if out != nil {
			var envelope struct {
				Data json.RawMessage `json:"data"`
			}
			if json.Unmarshal(rec.Body.Bytes(), &envelope) != nil || json.Unmarshal(envelope.Data, out) != nil {
				t.Fatal("invalid API response")
			}
		}
	}
	var state teams.Team
	call(owner, "POST", "/v1/teams", teams.CreateRequest{OperationID: "create", TeamID: teamID}, &state, 200)
	var other teams.Team
	call(outsider, "POST", "/v1/teams", teams.CreateRequest{OperationID: "create-other", TeamID: otherTeam}, &other, 200)
	var invite teams.Invitation
	call(owner, "POST", "/v1/teams/"+teamID+"/invitations", teams.InviteRequest{OperationID: "invite", ExpectedGeneration: state.Generation, AccountID: member.id}, &invite, 200)
	call(member, "POST", "/v1/team-invitations/"+invite.InvitationID+"/accept", teams.AcceptRequest{OperationID: "accept"}, &state, 200)
	call(owner, "POST", "/v1/teams/"+teamID+"/machines", teams.MachineRequest{OperationID: "share", ExpectedGeneration: state.Generation, MachineID: machine, Action: "share"}, &state, 200)
	call(owner, "POST", "/v1/teams/"+teamID+"/machine-grants", teams.MachineGrantRequest{OperationID: "files", ExpectedGeneration: state.Generation, MachineID: machine, Audience: "selected_member", AccountID: member.id, Capabilities: []string{"files"}, Active: true}, &state, 200)
	call(outsider, "GET", "/v1/machines/"+machine, nil, nil, 404)
	// Existing tunnel resources remain governed by the same membership/grants.
	mainTunnel, separateTunnel := "t44_tunnel_"+suffix, "t44_other_tunnel_"+suffix
	for _, item := range []struct{ id, account string }{{mainTunnel, owner.id}, {separateTunnel, outsider.id}} {
		sql(`WITH endpoint AS (SELECT gen_random_uuid() AS id) INSERT INTO paperboat.tunnels(id,account_id,name,access_mode,stable_endpoint_id,stable_endpoint,created_by_host_id,created_by_actor_id) SELECT $1,$2,$1,'team',id,'https://'||id||'.invalid.test','task44-host',$2 FROM endpoint`, item.id, item.account)
	}
	state, err = authority.Attach(ctx, owner.id, teamID, teams.AttachRequest{OperationID: "attach-tunnel", ExpectedGeneration: state.Generation, ResourceKind: "tunnel", ResourceID: mainTunnel, Active: true})
	if err != nil {
		t.Fatal(err)
	}
	state, err = authority.Grant(ctx, owner.id, teamID, teams.GrantRequest{OperationID: "grant-tunnel", ExpectedGeneration: state.Generation, ResourceKind: "tunnel", ResourceID: mainTunnel, AccountID: member.id, Permission: "use", Active: true})
	if err != nil {
		t.Fatal(err)
	}
	other, err = authority.Attach(ctx, outsider.id, otherTeam, teams.AttachRequest{OperationID: "attach-tunnel", ExpectedGeneration: other.Generation, ResourceKind: "tunnel", ResourceID: separateTunnel, Active: true})
	if err != nil {
		t.Fatal(err)
	}
	other, err = authority.Grant(ctx, outsider.id, otherTeam, teams.GrantRequest{OperationID: "grant-tunnel", ExpectedGeneration: other.Generation, ResourceKind: "tunnel", ResourceID: separateTunnel, AccountID: outsider.id, Permission: "use", Active: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = authority.Authorize(ctx, member.id, teamID, "tunnel", mainTunnel, "use"); err != nil {
		t.Fatal(err)
	}
	if _, e := machines.ExecDescriptor(ctx, member.id, source, machine, "task44-member", "task44-denied-exec"); !errors.Is(e, usermachines.ErrNotFound) {
		t.Fatalf("file grant exec denial: %v", e)
	}

	enrollment := controlplane.NewEnrollmentService(store, signer, writer, "https://task44.invalid", "task44-isolated-encryption-key")
	grant, err := enrollment.Issue(ctx, owner.id, "task44-enroll", environment, 3*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	proofPublic, proofPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := enrollment.Exchange(ctx, grant.Credential, proofPublic)
	if err != nil {
		t.Fatal(err)
	}
	observation := httptest.NewServer(runtimeObservation(metering.NewRuntimeRepository(store, "task44-isolated-encryption-key"), enrollment, 10, machines))
	defer observation.Close()
	now := time.Now().UTC()
	ownerToken, err := signer.SignCredential(mint.CredentialInput{Issuer: "https://task44.invalid", Audience: "paperboat-machine", Subject: owner.id, JTI: "task44-owner", IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute), CredentialClass: "terminal_operation", Scopes: []string{"terminal:operate"}, EnvironmentID: environment, MachineID: machine, UserID: owner.id, AccountID: owner.id, CLIClientSessionID: "task44-owner", SessionID: terminal})
	if err != nil {
		t.Fatal(err)
	}
	write("runtime.json", map[string]any{"endpoint": observation.URL, "environment_id": environment, "machine_id": machine, "terminal_session_id": terminal, "actor_account": owner.id, "client_id": "task44-owner", "identity_token": identity.Credential, "proof_private_key_base64": base64.RawURLEncoding.EncodeToString(proofPrivate), "proof_helper_id": identity.HelperID, "installation_generation": 1, "issuer": "https://task44.invalid", "key_id": "task44", "public_key": base64.RawURLEncoding.EncodeToString(public), "owner_token": ownerToken})
	child := exec.CommandContext(ctx, binary, "-test.v", "-test.run", "^TestTask44ConnectedRuntime$", "-test.timeout", "5m")
	child.Env = append(os.Environ(), "PAPERBOAT_TASK44_DIR="+directory, "TMPDIR="+directory)
	var runtimeLog bytes.Buffer
	child.Stdout, child.Stderr = &runtimeLog, &runtimeLog
	if err = child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = child.Process.Kill()
		_ = child.Wait()
		if t.Failed() {
			t.Log(runtimeLog.String())
		}
	}()
	var ready struct {
		PublicHost string `json:"public_host"`
		CertPEM    string `json:"cert_pem"`
	}
	waitJSON("runtime-ready.json", &ready)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(ready.CertPEM)) {
		t.Fatal("invalid runtime certificate")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}}
	defer transport.CloseIdleConnections()
	machines.ConfigureTerminalSessions(4, signer, &http.Client{Transport: transport, Timeout: 5 * time.Second})
	sql(`INSERT INTO paperboat.control_tunnel_nodes(id,edge_pool,protocol_version,process_epoch,state,ready,last_heartbeat_at) VALUES($1,'task44','1.0',$1,'ready',true,now())`, edge)
	sql(`UPDATE paperboat.control_connector_generations SET machine_id=$2,edge_pool='task44',edge_node_id=$3,state='admitted' WHERE environment_id=$1 AND generation=1`, environment, machine, edge)
	sql(`INSERT INTO paperboat.control_routes(id,environment_id,kind,public_host,target_host,target_port,desired_revision,applied_revision,applied_node_id,applied_generation) VALUES($1,$2,'runtime_https_wss',$3,'127.0.0.1',8080,1,1,$4,1)`, "route_"+suffix, environment, ready.PublicHost, edge)
	sharing, err := machines.GrantTerminalSessionSharing(ctx, owner.id, teamID, terminal, teams.TerminalSessionGrantRequest{OperationID: "share-terminal", ExpectedGeneration: state.Generation, Audience: "selected_member", AccountID: member.id, Role: "viewer", Active: true})
	if err != nil {
		t.Fatal(err)
	}
	state.Generation = sharing.Sharing.Generation
	descriptor, err := machines.ConnectSharedTerminalSession(ctx, member.id, source, member.cli, terminal)
	if err != nil || !descriptor.Connectable {
		t.Fatalf("shared descriptor connectable=%v err=%v", descriptor.Connectable, err)
	}
	token := descriptor.Terminal["auth"].(map[string]any)["token"].(string)
	actionWithFields := func(id, operation string, fields map[string]string) {
		t.Helper()
		_ = os.Remove(filepath.Join(directory, "result.json"))
		input := map[string]string{"id": id, "action": operation}
		for key, value := range fields {
			input[key] = value
		}
		write("action.json", input)
		var result struct {
			ID        string `json:"id"`
			OK        bool   `json:"ok"`
			ErrorCode string `json:"error_code"`
		}
		waitJSON("result.json", &result)
		if result.ID != id || !result.OK {
			t.Fatalf("runtime action %s failed: %s", operation, result.ErrorCode)
		}
	}
	action := func(id, operation, credential string) {
		actionWithFields(id, operation, map[string]string{"token": credential})
	}
	action("join", "attach", token)
	action("viewer-input", "viewer_input", token)
	assertTask43JoinAudit(t, store, teamID, member.id, 1)
	if _, e := machines.ConnectSharedTerminalSession(ctx, outsider.id, source, "task44-outsider", terminal); e == nil {
		t.Fatal("outsider shared attach authorized")
	}
	t.Log("current descriptor -> signed runtime attachment -> PostgreSQL audit; viewer input and outsider denied")

	// The same actors adopt a baseline and create a pending exact file request.
	ownerRepo, err := configs.ConnectRepository(ctx, owner.id, "github", os.Getenv("PAPERBOAT_TASK44_GITHUB_REPOSITORY_ID"), "Task44")
	if err != nil {
		t.Fatal(err)
	}
	memberRepo, err := configs.ConnectRepository(ctx, member.id, "github", os.Getenv("PAPERBOAT_TASK44_GITHUB_REPOSITORY_ID"), "Task44")
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := configs.SetTeamDefault(ctx, owner.id, teamID, ownerRepo.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, e := configs.SetTeamDefault(ctx, member.id, teamID, memberRepo.ID, baseline.Version); !errors.Is(e, controlplane.ErrAssignmentForbidden) {
		t.Fatalf("member default mutation: %v", e)
	}
	adopted, err := configs.AdoptTeamDefault(ctx, member.id, teamID, baseline.Version)
	if err != nil || adopted.RepositoryID != memberRepo.ID {
		t.Fatalf("adoption did not use member provider connection: %v", err)
	}
	task44QualifyConfigWorker(t, ctx, store, cfg, signer, enrollment, configs, configProvider, member.id, source, "env_"+source, memberRepo.ID, teamID, baseline.Version, actionWithFields)
	digest := sha256.Sum256([]byte("task44-approved-file"))
	files := []teaminbox.File{{Basename: "task44.txt", Size: int64(len("task44-approved-file")), SHA256: fmt.Sprintf("%x", digest)}}
	request, err := inbox.Create(ctx, teaminbox.RequestInput{RequestID: "t44_request_" + suffix, OperationID: "request", SenderAccount: member.id, SourceMachineID: source, DestinationMachineID: machine, BatchID: "t44_batch_" + suffix, Files: files, ExpiresAt: time.Now().Add(time.Minute)})
	if err != nil || request.Status != "pending" {
		t.Fatalf("pending inbox: %v", err)
	}
	if _, e := inbox.Decide(ctx, outsider.id, request.RequestID, "approved", request.DecisionGeneration); !errors.Is(e, teaminbox.ErrNotFound) {
		t.Fatalf("outsider approval: %v", e)
	}
	request, err = inbox.Decide(ctx, owner.id, request.RequestID, "approved", request.DecisionGeneration)
	if err != nil {
		t.Fatal(err)
	}
	fileDescriptor, err := machines.FileTransferDescriptorForRequest(ctx, member.id, source, machine, member.cli, "", request.RequestID, request.ManifestDigest)
	if err != nil {
		t.Fatal(err)
	}
	sendFile := func(id string, descriptor usermachines.FileTransferDescriptor, batchID, requestID string, own bool) {
		t.Helper()
		_ = os.Remove(filepath.Join(directory, "result.json"))
		write("action.json", map[string]any{"id": id, "action": "file", "token": descriptor.Auth["token"], "batch_id": batchID, "source_machine_id": descriptor.SourceMachineID, "initiating_user_id": descriptor.InitiatingUserID, "request_id": requestID, "own_device": own})
		var result struct {
			ID        string `json:"id"`
			OK        bool   `json:"ok"`
			ErrorCode string `json:"error_code"`
		}
		waitJSON("result.json", &result)
		if result.ID != id || !result.OK {
			t.Fatalf("%s delivery failed: %s", id, result.ErrorCode)
		}
	}
	sendFile("file-manual", fileDescriptor, request.BatchID, request.RequestID, false)
	call(member, "POST", "/v1/team-inbox/requests/"+request.RequestID+"/complete", map[string]string{"manifest_digest": request.ManifestDigest}, &request, 200)
	if request.Status != "completed" {
		t.Fatal("delivered transfer did not complete")
	}
	policy, err := inbox.Policy(ctx, owner.id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = inbox.SetPolicy(ctx, owner.id, teaminbox.Policy{Acceptance: "automatic"}, policy.Generation); err != nil {
		t.Fatal(err)
	}
	automatic, err := inbox.Create(ctx, teaminbox.RequestInput{RequestID: "t44_auto_" + suffix, OperationID: "automatic", SenderAccount: member.id, SourceMachineID: source, DestinationMachineID: machine, BatchID: "t44_auto_batch_" + suffix, Files: files, ExpiresAt: time.Now().Add(time.Minute)})
	if err != nil || automatic.Status != "approved" {
		t.Fatalf("automatic acceptance: %v", err)
	}
	autoDescriptor, err := machines.FileTransferDescriptorForRequest(ctx, member.id, source, machine, member.cli, "", automatic.RequestID, automatic.ManifestDigest)
	if err != nil {
		t.Fatal(err)
	}
	sendFile("file-automatic", autoDescriptor, automatic.BatchID, automatic.RequestID, false)
	call(member, "POST", "/v1/team-inbox/requests/"+automatic.RequestID+"/complete", map[string]string{"manifest_digest": automatic.ManifestDigest}, &automatic, 200)
	if automatic.Status != "completed" {
		t.Fatal("automatic transfer completion missing")
	}
	ownSource := "t44_own_source_" + suffix
	sql(`INSERT INTO paperboat.user_machines(id,user_id,environment_id,display_name,platform,architecture,workspace_root,state,seat_state,online,installation_generation) VALUES($1,$2,$3,'Own source','linux','amd64','/workspace','online','occupied',true,1)`, ownSource, owner.id, "env_"+ownSource)
	own, err := inbox.Create(ctx, teaminbox.RequestInput{RequestID: "t44_own_" + suffix, OperationID: "own", SenderAccount: owner.id, SourceMachineID: ownSource, DestinationMachineID: machine, BatchID: "t44_own_batch_" + suffix, Files: files, ExpiresAt: time.Now().Add(time.Minute)})
	if err != nil || own.Status != "not_required" {
		t.Fatalf("own-device acceptance bypass: %v", err)
	}
	ownDescriptor, err := machines.FileTransferDescriptor(ctx, owner.id, ownSource, machine, owner.cli, "")
	if err != nil {
		t.Fatal(err)
	}
	sendFile("file-own", ownDescriptor, "t44_own_batch_"+suffix, "", true)
	t.Log("manual and automatic exact-approved bytes delivered and completed; own-device bytes delivered without acceptance")
	request, err = inbox.Create(ctx, teaminbox.RequestInput{RequestID: "t44_pending_" + suffix, OperationID: "pending-removal", SenderAccount: member.id, SourceMachineID: source, DestinationMachineID: machine, BatchID: "t44_pending_batch_" + suffix, Files: files, ExpiresAt: time.Now().Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	sql(`INSERT INTO paperboat.environment_vault_teams(team_id,key_epoch) VALUES($1,1)`, teamID)
	sql(`INSERT INTO paperboat.environment_vault_team_members(team_id,account_id,grant_epoch) VALUES($1,$2,1)`, teamID, member.id)
	call(owner, "POST", "/v1/teams/"+teamID+"/actions", teams.MutationRequest{OperationID: "remove", ExpectedGeneration: state.Generation, Action: "remove", AccountID: member.id}, &state, 200)
	if state.ENVStatus != "rotation_pending" {
		t.Fatalf("ENV state=%s", state.ENVStatus)
	}
	if _, e := machines.ConnectSharedTerminalSession(ctx, member.id, source, member.cli, terminal); !errors.Is(e, usermachines.ErrTerminalSessionNotFound) {
		t.Fatalf("departed reconnect: %v", e)
	}
	action("departed-reconnect", "revoke_check", token)
	if _, e := inbox.Consume(ctx, member.id, request.RequestID, request.ManifestDigest); e == nil {
		t.Fatal("departed Inbox approval revived")
	}
	if _, e := configProvider.IssueUserRepositoryAccess(ctx, member.id, os.Getenv("PAPERBOAT_TASK44_GITHUB_REPOSITORY_ID"), "read"); e != nil {
		t.Fatal("PB departure incorrectly removed independent provider access")
	}
	if _, e := configs.TeamDefaultAdoption(ctx, member.id); e == nil {
		t.Fatal("departed adoption survived")
	}
	if _, e := configs.TeamDefault(ctx, member.id, teamID); !errors.Is(e, controlplane.ErrAssignmentForbidden) {
		t.Fatalf("departed default access: %v", e)
	}
	call(outsider, "GET", "/v1/teams/"+otherTeam, nil, &other, 200)
	if _, err = authority.Authorize(ctx, member.id, teamID, "tunnel", mainTunnel, "use"); !errors.Is(err, teams.ErrForbidden) {
		t.Fatalf("departed tunnel authority: %v", err)
	}
	if _, err = authority.Authorize(ctx, outsider.id, otherTeam, "tunnel", separateTunnel, "use"); err != nil {
		t.Fatalf("separate team tunnel lost: %v", err)
	}
	var activity teams.ActivityPage
	call(owner, "GET", "/v1/teams/"+teamID+"/activity", nil, &activity, 200)
	events := map[string]bool{}
	for _, item := range activity.Items {
		raw, _ := json.Marshal(item)
		for _, event := range []string{"terminal_session_joined", "config_default_adopted", "member_removed"} {
			if bytes.Contains(raw, []byte(event)) {
				events[event] = true
			}
		}
		if bytes.Contains(raw, []byte("identity_token")) || bytes.Contains(raw, []byte("private_key")) {
			t.Fatal("secret audit field")
		}
	}
	if !events["terminal_session_joined"] || !events["config_default_adopted"] {
		t.Fatal("integrated activity missing joins/adoption")
	}
	write("action.json", map[string]string{"id": "stop", "action": "stop"})
	if err := child.Wait(); err != nil {
		t.Fatal("runtime fixture did not cleanly stop")
	}
	call(owner, "POST", "/v1/teams/"+teamID+"/actions", teams.MutationRequest{OperationID: "delete", ExpectedGeneration: state.Generation, Action: "delete", Confirmation: teamID}, &state, 200)
	call(outsider, "POST", "/v1/teams/"+otherTeam+"/actions", teams.MutationRequest{OperationID: "delete-other", ExpectedGeneration: other.Generation, Action: "delete", Confirmation: otherTeam}, &other, 200)
	t.Log("same-team Inbox/config/ENV departure, denied stale runtime reconnect, owner PTY continuity, separate team and activity passed; isolated database owner removes all fixture rows")
}
