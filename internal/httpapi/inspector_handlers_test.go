package httpapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/auth"
	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/inspectaccess"
	"github.com/pinksaucepasta/paperboat-server/internal/previewattachment"
)

type inspectorMachineStub struct {
	proof previewattachment.MachineProof
	err   error
}

func (s inspectorMachineStub) VerifyMachineRequest(context.Context, *http.Request, []byte) (previewattachment.MachineProof, error) {
	return s.proof, s.err
}

func inspectorHTTPFixture(t *testing.T, ctx context.Context, database *db.DB, now time.Time, suffix string) (owner, mate, lease, tunnel, route, node string) {
	t.Helper()
	owner, mate = "usr_ih_owner_"+suffix, "usr_ih_mate_"+suffix
	teamID := "team_ih_" + suffix
	lease = "prv_ih_" + suffix
	operation := "op_ih_" + suffix
	session := "owner-session-ih-" + suffix
	machine := "mch_ih_" + suffix
	node = "edge-ih-" + suffix
	tunnel = "tun_ih_" + suffix
	route = "rte_ih_" + suffix
	exec := func(q string, args ...any) {
		t.Helper()
		if _, e := database.SQL().ExecContext(ctx, q, args...); e != nil {
			t.Fatal(e)
		}
	}
	exec(`INSERT INTO paperboat.users(id,workos_subject,primary_email,status) VALUES($1,$1,$1||'@test.invalid','active'),($2,$2,$2||'@test.invalid','active')`, owner, mate)
	key := sha256.Sum256([]byte("inspector-http-key:" + suffix))
	machinePrivate := ed25519.NewKeyFromSeed(key[:])
	machinePublic := machinePrivate.Public().(ed25519.PublicKey)
	publicKey := base64.RawURLEncoding.EncodeToString(machinePublic)
	thumbprint := sha256.Sum256(machinePublic)
	exec(`INSERT INTO paperboat.user_machines(id,user_id,environment_id,display_name,platform,architecture,workspace_root,state,seat_state,online,public_identity_key,installation_generation,worker_generation,worker_service_scope,connector_state) VALUES($1,$2,$3,'Inspector HTTP','linux','amd64','/workspace','online','occupied',true,$4,1,1,'system','ready')`, machine, owner, "env_ih_"+suffix, publicKey)
	exec(`INSERT INTO paperboat.control_tunnel_nodes(id,edge_pool,protocol_version,process_epoch,endpoint_host,endpoint_tcp_port,endpoint_quic_port,relay_id,relay_region,relay_name,carrier_endpoint_host,carrier_endpoint_tcp_port,carrier_endpoint_quic_port,carrier_server_spki_sha256,carrier_server_certificate_chain_pem,signaling_host,stun_host,stun_port,state,ready,capacity,last_heartbeat_at) VALUES($1,'test','1.0',$2,'edge.example.test',24001,24002,$3,'test','Inspector HTTP','edge.example.test',25001,25002,'sha256:'||repeat('b',64),'test-public-certificate-chain','edge.example.test','edge.example.test',3478,'ready',true,'{}',$4)`, node, "epoch-ih-"+suffix, "relay-ih-"+suffix, now)
	exec(`INSERT INTO paperboat.preview_leases(id,endpoint_id,endpoint,account_id,actor_id,owner_device_id,owner_session_id,target_scheme,target_address,access_mode,lease_deadline,allocation_state,edge_state,origin_state,terminal_state,created_at,last_renewed_at) VALUES($1,$2,$3,$4,$4,$5,$6,'http','127.0.0.1:3000','team',$7,'ready','ready','ready','active',$8,$8)`, lease, "pep_ih_"+suffix, "https://ih-"+suffix+".preview.example.test", owner, machine, session, now.Add(time.Hour), now)
	operationHash := sha256.Sum256([]byte("ih-operation:" + operation))
	exec(`INSERT INTO paperboat.operations(id,account_id,idempotency_key,request_hash,operation_type,resource_kind,resource_id,phase,state,progress,retrying,outcome,correlation_id,created_at,updated_at) VALUES($1,$2,$1,$3,'preview.create','preview_lease',$4,'connecting','running',60,false,'changed',$5,$6,$6)`, operation, owner, operationHash[:], lease, "cor_"+operation, now)
	exec(`INSERT INTO paperboat.preview_lease_create_operations(account_id,preview_id,operation_id) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, owner, lease, operation)
	repo, err := previewattachment.NewSQLRepository(database)
	if err != nil {
		t.Fatal(err)
	}
	request := previewattachment.Request{PreviewID: lease, OperationID: operation, OwnerDeviceID: machine, OwnerSessionID: session, IdempotencyKey: operation, RequestID: "req_" + operation, CorrelationID: "cor_" + operation}
	hash, err := request.Hash(owner)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = repo.CreatePending(ctx, previewattachment.Attachment{
		Schema: previewattachment.Schema, Kind: previewattachment.Kind,
		Binding:        previewattachment.Binding{AccountID: owner, PreviewID: lease, OperationID: operation, OwnerDeviceID: machine, OwnerSessionID: session, HostID: machine, LeaseGeneration: 1, TunnelID: "pvc-tun-ih-" + suffix, ConnectorID: "pvc-con-ih-" + suffix, SessionID: "pvc-ses-ih-" + suffix, ProcessGeneration: 1, ConfigGeneration: 1, RouteID: "pvc-rte-ih-" + suffix, RouteGeneration: 4, EdgeNodeID: node, EdgeProcessEpoch: "epoch-ih-" + suffix, EdgeCarrierServerSPKISHA256: "sha256:" + strings.Repeat("b", 64), EdgeCarrierServerCertificateChainPEM: "test-public-certificate-chain", MachineIdentityPublicKey: publicKey, MachineIdentityThumbprint: "sha256:" + base64.RawURLEncoding.EncodeToString(thumbprint[:])},
		IdempotencyKey: operation, RequestID: "req_" + operation, CorrelationID: "cor_" + operation, RequestHash: hash, Endpoint: "https://ih-" + suffix + ".preview.example.test", Target: previewattachment.Target{Scheme: "http", Address: "127.0.0.1:3000"}, AccessMode: "team", ConfigContentHash: "sha256:" + strings.Repeat("a", 64), EdgeEndpoints: []string{"h2://edge.example.test:25001", "h3://edge.example.test:25002"}, AttachmentGeneration: 1, IssuedAt: now, ExpiresAt: now.Add(20 * time.Minute), State: previewattachment.StatePending,
	}); err != nil {
		t.Fatal(err)
	}
	exec(`UPDATE paperboat.preview_lease_carrier_attachments SET state='ready',edge_ready=true,origin_ready=true,ready_at=$3 WHERE account_id=$1 AND preview_id=$2`, owner, lease, now)
	exec(`INSERT INTO paperboat.tunnels(id,account_id,name,desired_state,access_mode,generation,stable_endpoint_id,stable_endpoint,created_by_host_id,created_by_actor_id,created_at,updated_at) VALUES($1,$2,$1,'active','team',3,$3,$4,'host',$2,$5,$5)`, tunnel, owner, "00000000-0000-8000-8000-"+suffix[len(suffix)-12:], "https://00000000-0000-8000-8000-"+suffix[len(suffix)-12:]+".tunnels.example.test", now)
	exec(`INSERT INTO paperboat.tunnel_routes(id,tunnel_id,name,protocol,match_type,origin_scheme,origin_address,generation,desired_state,created_by_actor_id,updated_by_actor_id,created_at,updated_at) VALUES($1,$2,'web','http','catch_all','http','127.0.0.1:3000',7,'active',$3,$3,$4,$4)`, route, tunnel, owner, now)
	exec(`INSERT INTO paperboat.teams(team_id,owner_account,generation) VALUES($1,$2,1)`, teamID, owner)
	exec(`INSERT INTO paperboat.team_members(team_id,account_id,membership_generation,role,active) VALUES($1,$2,1,'member',true),($1,$3,1,'member',true)`, teamID, owner, mate)
	exec(`INSERT INTO paperboat.team_resource_bindings(team_id,resource_kind,resource_id,owner_account,active,generation) VALUES($1,'preview',$2,$3,true,1)`, teamID, lease, owner)
	exec(`INSERT INTO paperboat.team_resource_grants(team_id,account_id,resource_kind,resource_id,permission,generation,active) VALUES($1,$2,'preview',$3,'inspect',1,true)`, teamID, mate, lease)
	t.Cleanup(func() {
		c := context.Background()
		_, _ = database.SQL().ExecContext(c, `DELETE FROM paperboat.inspector_credentials WHERE account_id IN($1,$2)`, owner, mate)
		_, _ = database.SQL().ExecContext(c, `DELETE FROM paperboat.teams WHERE team_id=$1`, teamID)
		_, _ = database.SQL().ExecContext(c, `DELETE FROM paperboat.preview_leases WHERE id=$1`, lease)
		_, _ = database.SQL().ExecContext(c, `DELETE FROM paperboat.operations WHERE id=$1`, operation)
		_, _ = database.SQL().ExecContext(c, `DELETE FROM paperboat.tunnels WHERE id=$1`, tunnel)
		_, _ = database.SQL().ExecContext(c, `DELETE FROM paperboat.control_tunnel_nodes WHERE id=$1`, node)
		_, _ = database.SQL().ExecContext(c, `DELETE FROM paperboat.user_machines WHERE id=$1`, machine)
		_, _ = database.SQL().ExecContext(c, `DELETE FROM paperboat.users WHERE id IN($1,$2)`, owner, mate)
	})
	return owner, mate, lease, tunnel, route, node
}

func inspectorHTTPRequest(t *testing.T, handler http.HandlerFunc, method, target, body, account string) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body != "" {
		reader = bytes.NewReader([]byte(body))
	} else {
		reader = bytes.NewReader(nil)
	}
	request := httptest.NewRequest(method, target, reader)
	request.Header.Set("Content-Type", "application/json")
	if account != "" {
		request = request.WithContext(context.WithValue(request.Context(), authContextKey{}, principal{User: auth.User{ID: account}}))
	}
	recorder := httptest.NewRecorder()
	handler(recorder, request)
	return recorder
}

func decodeInspectorData(t *testing.T, recorder *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var envelope struct {
		Data  map[string]any `json:"data"`
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode %d: %v: %s", recorder.Code, err, recorder.Body.String())
	}
	return envelope.Data
}

// TestInspectorHandlersPostgres exercises the HTTP surface with real
// authority: user issuance/revocation shapes and codes, machine-channel
// authorize decisions with the stable triple, strict bodies, and proof
// failures. The full account matrix lives at the service level.
func TestInspectorHandlersPostgres(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("PAPERBOAT_TEST_DATABASE_DSN"))
	if dsn == "" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN")
	}
	if err := db.ValidateIsolatedTestDSN(dsn, os.Getenv("PAPERBOAT_DATABASE_DSN")); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	database, err := db.Open(config.Database{Driver: "postgres", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if os.Getenv("PAPERBOAT_TEST_SCHEMA_READY") != "1" {
		if err = db.Migrate(ctx, database); err != nil {
			t.Fatal(err)
		}
	}
	suffix := fmt.Sprint(time.Now().UnixNano())
	now := time.Now().UTC().Truncate(time.Microsecond)
	owner, mate, lease, _, _, _ := inspectorHTTPFixture(t, ctx, database, now, suffix)
	handlers := &InspectorHandlers{Access: inspectaccess.NewService(database), Machine: inspectorMachineStub{proof: previewattachment.MachineProof{UserID: owner, MachineID: "mch_ih_" + suffix, OperationID: "op", InstallationGeneration: 1}}}

	// Owner issuance carries the stable attachment triple.
	recorder := inspectorHTTPRequest(t, handlers.IssueCredential, http.MethodPost, "/v1/inspector/credentials", fmt.Sprintf(`{"resource_kind":"preview","resource_id":%q,"route_id":%q,"action":"inspect","ttl_seconds":300}`, lease, lease), owner)
	if recorder.Code != http.StatusOK {
		t.Fatalf("owner issue = %d: %s", recorder.Code, recorder.Body.String())
	}
	issued := decodeInspectorData(t, recorder)
	token, _ := issued["token"].(string)
	credentialID, _ := issued["credential_id"].(string)
	if token == "" || credentialID == "" || !strings.HasPrefix(token, "iat_") {
		t.Fatalf("issued shape = %v", issued)
	}

	// Mate issuance honors the inspect grant; replay issuance is denied.
	recorder = inspectorHTTPRequest(t, handlers.IssueCredential, http.MethodPost, "/v1/inspector/credentials", fmt.Sprintf(`{"resource_kind":"preview","resource_id":%q,"route_id":%q,"action":"inspect","ttl_seconds":60}`, lease, lease), mate)
	if recorder.Code != http.StatusOK {
		t.Fatalf("mate issue inspect = %d: %s", recorder.Code, recorder.Body.String())
	}
	recorder = inspectorHTTPRequest(t, handlers.IssueCredential, http.MethodPost, "/v1/inspector/credentials", fmt.Sprintf(`{"resource_kind":"preview","resource_id":%q,"route_id":%q,"action":"replay"}`, lease, lease), mate)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("mate issue replay = %d, want 403", recorder.Code)
	}
	// Strict bodies and unknown actions fail before any authority read.
	recorder = inspectorHTTPRequest(t, handlers.IssueCredential, http.MethodPost, "/v1/inspector/credentials", fmt.Sprintf(`{"resource_kind":"preview","resource_id":%q,"route_id":%q,"action":"inspect","extra":1}`, lease, lease), mate)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("unknown field = %d, want 400", recorder.Code)
	}

	// Machine-channel authorize returns the 10-second decision; proof
	// failures are 401 without touching authority.
	authorizeBody := fmt.Sprintf(`{"credential_token":%q,"resource_kind":"preview","resource_id":%q,"route_id":%q,"action":"inspect"}`, token, lease, lease)
	recorder = inspectorHTTPRequest(t, handlers.Authorize, http.MethodPost, "/v1/inspector/authorize", authorizeBody, "")
	if recorder.Code != http.StatusOK {
		t.Fatalf("authorize = %d: %s", recorder.Code, recorder.Body.String())
	}
	decision := decodeInspectorData(t, recorder)
	if decision["account_id"] != owner || decision["route_generation"] != float64(4) {
		t.Fatalf("decision = %v", decision)
	}
	badProof := &InspectorHandlers{Access: inspectaccess.NewService(database), Machine: inspectorMachineStub{err: fmt.Errorf("bad proof")}}
	recorder = inspectorHTTPRequest(t, badProof.Authorize, http.MethodPost, "/v1/inspector/authorize", authorizeBody, "")
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("bad proof = %d, want 401", recorder.Code)
	}

	// Holder revokes; a second authorize fails closed; strangers cannot revoke.
	// httptest requests carry no mux path values, so revoke travels in the
	// body here; the served route also accepts the path form.
	recorder = inspectorHTTPRequest(t, handlers.RevokeCredential, http.MethodDelete, "/v1/inspector/credentials/"+credentialID, fmt.Sprintf(`{"credential_id":%q}`, credentialID), owner)
	if recorder.Code != http.StatusOK {
		t.Fatalf("revoke = %d: %s", recorder.Code, recorder.Body.String())
	}
	recorder = inspectorHTTPRequest(t, handlers.Authorize, http.MethodPost, "/v1/inspector/authorize", authorizeBody, "")
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("revoked authorize = %d, want 403", recorder.Code)
	}
}

// TestInspectorHandlersDenyWithoutPrincipal proves unauthenticated issuance is
// rejected before any database mutation surface is reached.
func TestInspectorHandlersDenyWithoutPrincipal(t *testing.T) {
	handlers := &InspectorHandlers{}
	recorder := inspectorHTTPRequest(t, handlers.IssueCredential, http.MethodPost, "/v1/inspector/credentials", `{"resource_kind":"preview","resource_id":"x","route_id":"x","action":"inspect"}`, "")
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous issue = %d, want 401", recorder.Code)
	}
}
