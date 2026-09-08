package peersessions

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/controlplane"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/metering"
)

// Exercise native lifecycle with the real authority fixture instead of creating
// another account/certificate/access fixture with subtly different semantics.
func exerciseNativeRelayLifecycle(t *testing.T, store *db.DB, network *NetworkService, account, endpoint, node string) {
	t.Helper()
	ctx := context.Background()
	if _, err := store.SQL().ExecContext(ctx, `UPDATE paperboat.control_tunnel_nodes SET transports=ARRAY['derp_quic','derp_wss','peer_relay_udp'] WHERE id=$1`, node); err != nil {
		t.Fatal(err)
	}
	credential := strings.Repeat("relay-lifecycle-test", 3)
	edge := controlplane.NewEdgeService(store, credential)
	api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/test/native-relay/revoke" && r.Method == http.MethodPost && r.Header.Get("Authorization") == "Bearer "+credential {
			if _, err := store.SQL().ExecContext(r.Context(), `UPDATE paperboat.cli_client_sessions SET state='revoked',revoked_at=now() WHERE id=$1`, endpoint); err != nil {
				http.Error(w, "revocation failed", 500)
				return
			}
			w.WriteHeader(204)
			return
		}
		edge.Handler().ServeHTTP(w, r)
	}))
	defer api.Close()
	post := func(path string, in any, authenticated bool, want int) map[string]any {
		t.Helper()
		body, _ := json.Marshal(in)
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, api.URL+path, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if authenticated {
			req.Header.Set("Authorization", "Bearer "+credential)
		}
		resp, err := api.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != want {
			t.Fatalf("%s status=%d want=%d", path, resp.StatusCode, want)
		}
		var out map[string]any
		if want == 200 && json.NewDecoder(resp.Body).Decode(&out) != nil {
			t.Fatal("invalid lifecycle response")
		}
		return out
	}
	start := map[string]any{"node_id": node, "expected_generation": 1, "process_epoch": "native-epoch-two"}
	post("/v1/relay/nodes/start", start, false, 401)
	post("/v1/relay/nodes/start", map[string]any{"node_id": "not-provisioned", "expected_generation": 1, "process_epoch": "new"}, true, 409)
	first := post("/v1/relay/nodes/start", start, true, 200)
	if first["node_generation"] != float64(2) {
		t.Fatal("startup did not advance generation")
	}
	if first["peer_relay"] == nil {
		t.Fatal("registered peer-relay service identity absent from lease")
	}
	if int64(first["expires_at"].(float64)) > time.Now().Add(15*time.Second).Unix() {
		t.Fatal("control lease exceeded 15 seconds")
	}
	var registryExpiry time.Time
	if err := store.SQL().QueryRowContext(ctx, `SELECT registry_expires_at FROM paperboat.control_tunnel_nodes WHERE id=$1`, node).Scan(&registryExpiry); err != nil || time.Until(registryExpiry) < 55*time.Second {
		t.Fatal("registry lease too short for credential renewal")
	}
	retry := post("/v1/relay/nodes/start", start, true, 200)
	if retry["node_generation"] != first["node_generation"] {
		t.Fatal("retry advanced generation")
	}
	exerciseHeartbeatRelayAuthority(t, store, account, endpoint)
	var gen, floor int64
	if err := store.SQL().QueryRowContext(ctx, `SELECT config_generation,relay_revocation_generation FROM paperboat.peer_network_identities WHERE user_id=$1 AND endpoint_id=$2`, account, endpoint).Scan(&gen, &floor); err != nil {
		t.Fatal(err)
	}
	observe := map[string]any{"node_id": node, "node_generation": 2, "process_epoch": "native-epoch-two", "ready": true, "draining": false, "capacity_used": 1, "subjects": []any{map[string]any{"account_id": account, "endpoint_id": endpoint, "generation": gen}}}
	result := post("/v1/relay/nodes/observe", observe, true, 200)
	if len(result["revocations"].([]any)) != 0 {
		t.Fatal("current authority revoked")
	}
	if _, err := network.Configuration(ctx, NetworkConfigRequest{OperationID: "operation_native_relay_renewal", UserID: account, EndpointID: endpoint}); err != nil {
		t.Fatal(err)
	}
	result = post("/v1/relay/nodes/observe", observe, true, 200)
	if len(result["revocations"].([]any)) != 0 {
		t.Fatal("ordinary configuration renewal revoked carrier")
	}
	var nextFloor int64
	if err := store.SQL().QueryRowContext(ctx, `SELECT relay_revocation_generation FROM paperboat.peer_network_identities WHERE user_id=$1 AND endpoint_id=$2`, account, endpoint).Scan(&nextFloor); err != nil || nextFloor != floor {
		t.Fatal("normal refresh advanced revocation floor")
	}
	if _, err := store.SQL().ExecContext(ctx, `UPDATE paperboat.cli_client_sessions SET state='revoked',revoked_at=now() WHERE id=$1`, endpoint); err != nil {
		t.Fatal(err)
	}
	result = post("/v1/relay/nodes/observe", observe, true, 200)
	revocations := result["revocations"].([]any)
	if len(revocations) != 1 || int64(revocations[0].(map[string]any)["generation"].(float64)) <= gen {
		t.Fatal("session revocation floor not distributed")
	}
	observe["node_generation"] = 1
	post("/v1/relay/nodes/observe", observe, true, 409)
	observe["node_generation"] = 2
	observe["process_epoch"] = "stale"
	post("/v1/relay/nodes/observe", observe, true, 409)
	observe["process_epoch"] = "native-epoch-two"
	observe["capacity_used"] = 101
	post("/v1/relay/nodes/observe", observe, true, 409)
	observe["capacity_used"] = 1
	observe["draining"] = true
	post("/v1/relay/nodes/observe", observe, true, 200)
	observe["draining"] = false
	post("/v1/relay/nodes/observe", observe, true, 409)
	start["expected_generation"] = 2
	start["process_epoch"] = "native-epoch-three"
	post("/v1/relay/nodes/start", start, true, 200)
	post("/v1/relay/nodes/observe", observe, true, 409)
	observe["node_generation"] = 3
	observe["process_epoch"] = "native-epoch-three"
	post("/v1/relay/nodes/observe", observe, true, 200)
	if _, err := store.SQL().ExecContext(ctx, `UPDATE paperboat.control_tunnel_nodes SET registry_expires_at=$2 WHERE id=$1`, node, time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	post("/v1/relay/nodes/observe", observe, true, 409)
	if binary := os.Getenv("PAPERBOAT_RELAY_LIFECYCLE_CLIENT"); binary != "" {
		// The connected lifecycle carrier fixture runs the DERP-only node role.
		if _, err := store.SQL().ExecContext(ctx, `UPDATE paperboat.control_tunnel_nodes SET state='registered',ready=false,roles=ARRAY['relay'],transports=ARRAY['derp_quic','derp_wss'],peer_relay_wireguard_public_key=NULL,peer_relay_disco_public_key=NULL,peer_relay_virtual_address=NULL WHERE id=$1`, node); err != nil {
			t.Fatal(err)
		}
		if _, err := store.SQL().ExecContext(ctx, `UPDATE paperboat.cli_client_sessions SET state='active',revoked_at=NULL WHERE id=$1`, endpoint); err != nil {
			t.Fatal(err)
		}
		if _, err := network.Configuration(ctx, NetworkConfigRequest{OperationID: "operation_native_relay_external", UserID: account, EndpointID: endpoint}); err != nil {
			t.Fatal(err)
		}
		var generation uint64
		if err := store.SQL().QueryRowContext(ctx, `SELECT config_generation FROM paperboat.peer_network_identities WHERE user_id=$1 AND endpoint_id=$2`, account, endpoint).Scan(&generation); err != nil {
			t.Fatal(err)
		}
		fixture := map[string]any{"URL": api.URL, "Credential": credential, "NodeID": node, "Generation": 3, "AccountID": account, "EndpointID": endpoint, "SubjectGeneration": generation, "CA": api.Certificate().Raw}
		raw, _ := json.Marshal(fixture)
		path := filepath.Join(t.TempDir(), "lifecycle.json")
		if os.WriteFile(path, raw, 0600) != nil {
			t.Fatal("cannot write lifecycle fixture")
		}
		command := exec.CommandContext(ctx, binary, "-test.run", "^TestNativeRelayLifecycleRevokesConnectedCarrier$", "-test.v", "-test.timeout=20s")
		command.Env = append(os.Environ(), "PAPERBOAT_RELAY_LIFECYCLE_FIXTURE="+path)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("packaged lifecycle client: %v\n%s", err, output)
		} else {
			t.Logf("packaged lifecycle client: %s", output)
		}
	}
}

// Heartbeats update receipt time even when readiness is unchanged. They must not
// invalidate either endpoint's already issued regional grants.
func exerciseHeartbeatRelayAuthority(t *testing.T, store *db.DB, account, cli string) {
	t.Helper()
	ctx := context.Background()
	var machine, environment string
	if err := store.SQL().QueryRowContext(ctx, `SELECT user_machine_id,environment_id FROM paperboat.user_machine_access_sessions WHERE user_id=$1 AND cli_client_session_id=$2 LIMIT 1`, account, cli).Scan(&machine, &environment); err != nil {
		t.Fatal(err)
	}
	read := func() [4]int64 {
		t.Helper()
		var result [4]int64
		for i, endpoint := range []string{machine, cli} {
			if err := store.SQL().QueryRowContext(ctx, `SELECT config_generation,relay_revocation_generation FROM paperboat.peer_network_identities WHERE user_id=$1 AND endpoint_id=$2`, account, endpoint).Scan(&result[i*2], &result[i*2+1]); err != nil {
				t.Fatal(err)
			}
		}
		return result
	}
	repository := metering.NewRuntimeRepository(store, "")
	observation := metering.RuntimeObservation{ProjectID: environment, MachineID: machine, ObservedAt: time.Now().UTC(), ReporterVersion: "test"}
	if err := repository.RecordRuntimeObservation(ctx, observation); err != nil {
		t.Fatal(err)
	}
	before := read()
	for range 2 {
		if err := repository.RecordRuntimeObservation(ctx, observation); err != nil {
			t.Fatal(err)
		}
		if after := read(); after != before {
			t.Fatalf("unchanged heartbeat invalidated machine/CLI authority: before=%v after=%v", before, after)
		}
	}
	// Roll back each actual mutation so the shared authority fixture remains intact.
	for _, change := range []string{"state='offline'", "seat_state='released'", "revoked_at=now()", "deleted_at=now()", "installation_generation=installation_generation+1"} {
		tx, err := store.SQL().BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		func() {
			defer tx.Rollback()
			if _, err := tx.ExecContext(ctx, "UPDATE paperboat.user_machines SET "+change+" WHERE id=$1", machine); err != nil {
				t.Fatal(err)
			}
			for i, endpoint := range []string{machine, cli} {
				var floor int64
				if err := tx.QueryRowContext(ctx, `SELECT relay_revocation_generation FROM paperboat.peer_network_identities WHERE user_id=$1 AND endpoint_id=$2`, account, endpoint).Scan(&floor); err != nil {
					t.Fatal(err)
				}
				if floor <= before[i*2+1] {
					t.Fatalf("actual %s did not fence endpoint %d", change, i)
				}
			}
		}()
	}
}
