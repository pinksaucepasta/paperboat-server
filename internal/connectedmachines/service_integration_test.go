package connectedmachines

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/agentunnel"
	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
)

func TestReserveBandwidthConsumesIncludedThenTopups(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID, machineID := "usr_cm_bandwidth_"+suffix, "cm_bandwidth_"+suffix
	if _, err := store.SQL().ExecContext(ctx, `
INSERT INTO paperboat.users (id, workos_subject, primary_email, status)
VALUES ($1, $2, $3, 'active')`, userID, "workos_"+suffix, "cm-bandwidth-"+suffix+"@example.test"); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, err := store.SQL().ExecContext(ctx, `
INSERT INTO paperboat.connected_machine_entitlements
  (id, user_id, provider_subscription_id, product_code, state, seat_quantity, allowance_bytes, current_period_start, current_period_end)
VALUES ($1, $2, $3, 'connected-test', 'active', 1, 100, $4, $5)`, "cme_"+suffix, userID, "sub_"+suffix, now.Add(-time.Hour), now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `
INSERT INTO paperboat.connected_machines
  (id, user_id, environment_id, display_name, platform, architecture, workspace_root, state, seat_state, online)
VALUES ($1, $2, $3, $4, 'linux', 'amd64', '/home/example', 'online', 'occupied', true)`, machineID, userID, "env_"+suffix, "Machine "+suffix); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `
INSERT INTO paperboat.connected_machine_bandwidth_topups
  (id, user_id, provider_order_id, purchased_bytes, remaining_bytes)
VALUES ($1, $2, $3, 20, 20)`, "cmbt_"+suffix, userID, "order_"+suffix); err != nil {
		t.Fatal(err)
	}
	service := New(store, audit.NewWriter(store), Policy{}, nil)
	reservation, err := service.ReserveBandwidth(ctx, machineID, 125)
	if err != nil {
		t.Fatal(err)
	}
	if reservation.GrantedBytes != 120 || !reservation.Exhausted {
		t.Fatalf("reservation = %+v, want 120 bytes and exhausted", reservation)
	}
	var included, topup int64
	if err := store.SQL().QueryRowContext(ctx, `
SELECT consumed_included_bytes, consumed_topup_bytes
FROM paperboat.connected_machine_bandwidth_periods
WHERE connected_machine_id = $1`, machineID).Scan(&included, &topup); err != nil {
		t.Fatal(err)
	}
	if included != 100 || topup != 20 {
		t.Fatalf("period consumed included/topup = %d/%d", included, topup)
	}
	var topupState string
	var remaining int64
	if err := store.SQL().QueryRowContext(ctx, `
SELECT state, remaining_bytes FROM paperboat.connected_machine_bandwidth_topups WHERE id = $1`, "cmbt_"+suffix).Scan(&topupState, &remaining); err != nil {
		t.Fatal(err)
	}
	if topupState != "exhausted" || remaining != 0 {
		t.Fatalf("top-up state/remaining = %q/%d", topupState, remaining)
	}
	reservation, err = service.ReserveBandwidth(ctx, machineID, 1)
	if err != nil {
		t.Fatal(err)
	}
	if reservation.GrantedBytes != 0 || !reservation.Exhausted {
		t.Fatalf("exhausted reservation = %+v", reservation)
	}
	if _, err := store.SQL().ExecContext(ctx, `UPDATE paperboat.connected_machines SET state = 'disconnected' WHERE id = $1`, machineID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.ReserveBandwidth(ctx, machineID, 1); !errors.Is(err, ErrBandwidthDenied) {
		t.Fatalf("disconnected machine reservation error = %v", err)
	}
}

func TestConnectIssuesEnvironmentBoundDescriptor(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID, machineID, environmentID := "usr_cm_connect_"+suffix, "cm_connect_"+suffix, "env_connect_"+suffix
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users (id,workos_subject,primary_email,status) VALUES ($1,$2,$3,'active')`, userID, "workos_"+suffix, "cm-connect-"+suffix+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.connected_machines (id,user_id,environment_id,display_name,platform,architecture,workspace_root,state,seat_state,online,agentunnel_route_id,agentunnel_client_id,agentunnel_http_base_url,agentunnel_websocket_base_url) VALUES ($1,$2,$3,'Studio Mac','darwin','arm64','/Users/paperboat','online','occupied',true,'tun_1','cli_1','https://machine.example','wss://machine.example')`, machineID, userID, environmentID); err != nil {
		t.Fatal(err)
	}
	if err := store.Queries().CreateDefaultConnectedMachineTerminalSession(ctx, dbsqlc.CreateDefaultConnectedMachineTerminalSessionParams{ID: "cmts_default_" + machineID, ConnectedMachineID: machineID, LaunchCwd: "/Users/paperboat"}); err != nil {
		t.Fatal(err)
	}
	service := New(store, audit.NewWriter(store), Policy{}, nil)
	service.ConfigureProvisioning(agentunnel.FakeClient{}, "test-key")
	service.ConfigureAccess(agentunnel.FakeCredentialIssuer{}, "https://api.paperboat.test", 5*time.Minute, 1024, []string{"image/png"}, 60)
	response, err := service.Connect(ctx, userID, machineID, "cls_1")
	if err != nil {
		t.Fatal(err)
	}
	if !response.Connectable || response.ConnectedMachineID != machineID || response.Environment["environment_id"] != environmentID || response.Environment["connected_machine_id"] != machineID {
		t.Fatalf("response = %#v", response)
	}
	if response.Terminal["http_base_url"] != "https://machine.example" || response.Terminal["auth"] == nil || response.Upload["auth"] == nil {
		t.Fatalf("descriptor = %#v", response)
	}
}

func TestDisconnectRevokesMintedPapercodeSessionsAndRetriesOfflineConnector(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userID, machineID, environmentID := "usr_cm_revoke_"+suffix, "cm_revoke_"+suffix, "env_revoke_"+suffix
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.users (id,workos_subject,primary_email,status) VALUES ($1,$2,$3,'active')`, userID, "workos_"+suffix, "cm-revoke-"+suffix+"@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SQL().ExecContext(ctx, `INSERT INTO paperboat.connected_machines (id,user_id,environment_id,display_name,platform,architecture,workspace_root,state,seat_state,online,agentunnel_route_id,agentunnel_client_id,agentunnel_http_base_url,agentunnel_websocket_base_url) VALUES ($1,$2,$3,'Studio Mac','darwin','arm64','/Users/paperboat','online','occupied',true,'tun_1','cli_1','https://machine.example','wss://machine.example')`, machineID, userID, environmentID); err != nil {
		t.Fatal(err)
	}
	if err := store.Queries().CreateDefaultConnectedMachineTerminalSession(ctx, dbsqlc.CreateDefaultConnectedMachineTerminalSessionParams{ID: "cmts_default_" + machineID, ConnectedMachineID: machineID, LaunchCwd: "/Users/paperboat"}); err != nil {
		t.Fatal(err)
	}
	issuer := &recordingIssuer{}
	service := New(store, audit.NewWriter(store), Policy{}, nil)
	service.ConfigureProvisioning(agentunnel.FakeClient{}, "test-key")
	service.ConfigureAccess(issuer, "https://api.paperboat.test", 5*time.Minute, 1024, []string{"image/png"}, 60)
	if _, err := service.Connect(ctx, userID, machineID, "cls_1"); err != nil {
		t.Fatal(err)
	}
	var active int
	if err := store.SQL().QueryRowContext(ctx, `SELECT count(*) FROM paperboat.connected_machine_access_sessions WHERE connected_machine_id=$1 AND state='active'`, machineID).Scan(&active); err != nil {
		t.Fatal(err)
	}
	if active != 1 {
		t.Fatalf("active access sessions = %d, want 1", active)
	}
	issuer.failRevocation = true
	if err := service.Disconnect(ctx, userID, machineID); err == nil {
		t.Fatal("Disconnect succeeded while Papercode was unavailable")
	}
	var propagated bool
	if err := store.SQL().QueryRowContext(ctx, `SELECT papercode_revoked_at IS NOT NULL FROM paperboat.connected_machine_access_sessions WHERE connected_machine_id=$1`, machineID).Scan(&propagated); err != nil {
		t.Fatal(err)
	}
	if propagated {
		t.Fatal("revocation was marked propagated after a failed downstream call")
	}
	issuer.failRevocation = false
	if err := service.RetryPendingRevocations(ctx); err != nil {
		t.Fatal(err)
	}
	if err := store.SQL().QueryRowContext(ctx, `SELECT papercode_revoked_at IS NOT NULL FROM paperboat.connected_machine_access_sessions WHERE connected_machine_id=$1`, machineID).Scan(&propagated); err != nil {
		t.Fatal(err)
	}
	if !propagated || len(issuer.revocations) != 2 {
		t.Fatalf("propagated=%v revocations=%d, want true and 2", propagated, len(issuer.revocations))
	}
}

type recordingIssuer struct {
	agentunnel.FakeCredentialIssuer
	failRevocation bool
	revocations    []agentunnel.CredentialRevocationInput
}

func (i *recordingIssuer) RevokeCLI(_ context.Context, input agentunnel.CredentialRevocationInput) error {
	i.revocations = append(i.revocations, input)
	if i.failRevocation {
		return errors.New("papercode unavailable")
	}
	return nil
}

func testStore(t *testing.T) *db.DB {
	t.Helper()
	dsn := os.Getenv("PAPERBOAT_TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN to run connected-machine integration tests")
	}
	store, err := db.Open(config.Database{Driver: "postgres", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := db.Migrate(context.Background(), store); err != nil {
		t.Fatal(err)
	}
	return store
}
