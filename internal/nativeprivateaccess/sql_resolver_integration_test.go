package nativeprivateaccess

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/testutil"
)

func TestSQLResolverUsesCurrentPrivateDesiredStateOnPostgres(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("PAPERBOAT_TEST_DATABASE_DSN"))
	if dsn == "" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN to run native-private PostgreSQL acceptance")
	}
	if err := db.ValidateIsolatedTestDSN(dsn, os.Getenv("PAPERBOAT_DATABASE_DSN")); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	store, err := db.Open(config.Database{Driver: "postgres", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err = db.Migrate(ctx, store); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	suffix := fmt.Sprint(now.UnixNano())
	userID, cliID, machineID, envID := "usr_np_"+suffix, "cli_np_"+suffix, "mch_np_"+suffix, "env_np_"+suffix
	previewID, tunnelID, routeID := "prv_np_"+suffix, "tun_np_"+suffix, "rte_np_"+suffix
	exec := func(query string, args ...any) {
		t.Helper()
		if _, execErr := store.SQL().ExecContext(ctx, query, args...); execErr != nil {
			t.Fatal(execErr)
		}
	}
	t.Cleanup(func() {
		_, _ = store.SQL().ExecContext(context.Background(), `DELETE FROM paperboat.users WHERE id=$1`, userID)
	})
	exec(`INSERT INTO paperboat.users(id,workos_subject,primary_email,status) VALUES($1,$2,$3,'active')`, userID, "workos_"+userID, userID+"@example.test")
	exec(`INSERT INTO paperboat.cli_client_sessions(id,user_id,client_id,client_label,device_type,os,scopes,state,created_at,approved_at) VALUES($1,$2,$3,'native private test','desktop','test',ARRAY['projects:connect'],'active',$4,$4)`, cliID, userID, "client_"+suffix, now)
	exec(`INSERT INTO paperboat.control_environments(id,workspace_id,owner_user_id) VALUES($1,$2,$3)`, envID, "workspace_"+suffix, userID)
	exec(`INSERT INTO paperboat.user_machines(id,user_id,environment_id,display_name,platform,architecture,workspace_root,state,seat_state,online,installation_generation) VALUES($1,$2,$3,'Native private host','linux','amd64','/workspace','online','occupied',true,1)`, machineID, userID, envID)
	exec(`INSERT INTO paperboat.user_machine_access_sessions(id,user_machine_id,user_id,environment_id,cli_client_session_id,http_base_url,helper_terminal_session_id,expires_at) VALUES($1,$2,$3,$4,$5,'https://machine.example.test',$6,$7)`, "umas_np_"+suffix, machineID, userID, envID, cliID, "terminal_np_"+suffix, now.Add(time.Hour))
	exec(`INSERT INTO paperboat.preview_leases(id,endpoint_id,endpoint,account_id,actor_id,owner_device_id,owner_session_id,target_scheme,target_address,access_mode,lease_deadline,allocation_state,edge_state,origin_state,terminal_state,generation,created_at,last_renewed_at) VALUES($1,$2,$3,$4,$4,$5,$6,'http','127.0.0.1:3000','private',$7,'ready','ready','ready','active',4,$8,$8)`, previewID, "pep_np_"+suffix, "https://preview-"+suffix+".example.test", userID, machineID, "owner_np_"+suffix, now.Add(time.Hour), now)
	endpointID := testutil.EndpointUUID("native-private:" + suffix)
	exec(`INSERT INTO paperboat.tunnels(id,account_id,name,desired_state,access_mode,generation,stable_endpoint_id,stable_endpoint,created_by_host_id,created_by_actor_id,summary_code,created_at,updated_at) VALUES($1,$2,$3,'active','private',5,$4,$5,$6,$2,'ready',$7,$7)`, tunnelID, userID, "native-private-"+suffix, endpointID, "https://"+endpointID+".tunnels.example.test", machineID, now)
	exec(`INSERT INTO paperboat.tunnel_routes(id,tunnel_id,name,protocol,match_type,match_hostname,origin_scheme,origin_address,desired_state,generation,created_by_actor_id,updated_by_actor_id) VALUES($1,$2,'tcp','private_tcp','exact',$3,'tcp','127.0.0.1:5432','active',6,$4,$4)`, routeID, tunnelID, "native-"+suffix+".example.test", userID)

	resolver, err := NewSQLResolver(store)
	if err != nil {
		t.Fatal(err)
	}
	resolver.now = func() time.Time { return now }
	preview, err := resolver.ResolveNativePrivate(ctx, Request{AccountID: userID, UserID: userID, CLIClientSessionID: cliID, ResourceKind: "preview", ResourceID: previewID, RouteID: previewID, Protocol: "http"})
	if err != nil || preview.MachineID != machineID || preview.AccessSessionID != "umas_np_"+suffix || preview.TargetAddress != "127.0.0.1:3000" || preview.ResourceGeneration != 4 || preview.RouteGeneration != 4 || preview.TargetGeneration != 4 {
		t.Fatalf("preview=%+v err=%v", preview, err)
	}
	tunnel, err := resolver.ResolveNativePrivate(ctx, Request{AccountID: userID, UserID: userID, CLIClientSessionID: cliID, ResourceKind: "tunnel", ResourceID: tunnelID, RouteID: routeID, Protocol: "tcp"})
	if err != nil || tunnel.MachineID != machineID || tunnel.TargetAddress != "127.0.0.1:5432" || tunnel.ResourceGeneration != 5 || tunnel.RouteGeneration != 6 || tunnel.TargetGeneration != 6 {
		t.Fatalf("tunnel=%+v err=%v", tunnel, err)
	}
	selected, err := resolver.ResolveNativePrivate(ctx, Request{AccountID: userID, UserID: userID, CLIClientSessionID: cliID, Selector: "tcp"})
	if err != nil || selected.ResourceID != tunnelID || selected.RouteID != routeID || selected.AccessSessionID != "umas_np_"+suffix {
		t.Fatalf("selected=%+v err=%v", selected, err)
	}
	for name, request := range map[string]Request{
		"route substitution": {AccountID: userID, UserID: userID, CLIClientSessionID: cliID, ResourceKind: "tunnel", ResourceID: tunnelID, RouteID: previewID, Protocol: "tcp"},
		"foreign session":    {AccountID: userID, UserID: userID, CLIClientSessionID: "cli_foreign", ResourceKind: "preview", ResourceID: previewID, RouteID: previewID, Protocol: "http"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, resolveErr := resolver.ResolveNativePrivate(ctx, request); !errors.Is(resolveErr, ErrDenied) {
				t.Fatalf("error=%v, want denied", resolveErr)
			}
		})
	}
	exec(`UPDATE paperboat.user_machine_access_sessions SET state='revoked',revoked_at=$2 WHERE cli_client_session_id=$1`, cliID, now)
	if _, err = resolver.ResolveNativePrivate(ctx, Request{AccountID: userID, UserID: userID, CLIClientSessionID: cliID, ResourceKind: "preview", ResourceID: previewID, RouteID: previewID, Protocol: "http"}); !errors.Is(err, ErrDenied) {
		t.Fatalf("revoked session error=%v, want denied", err)
	}
}
