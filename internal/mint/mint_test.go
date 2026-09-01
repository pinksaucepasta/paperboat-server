package mint

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"
)

func testKey(seedByte byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed([]byte(strings.Repeat(string([]byte{seedByte}), ed25519.SeedSize)))
}

func TestSignPublishesFrozenClaims(t *testing.T) {
	provider, err := New([]Key{{ID: "key-2", PrivateKey: testKey(2)}, {ID: "key-1", PrivateKey: testKey(1)}}, "key-2", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	issuedAt := time.Unix(1_700_000_000, 0)
	token, err := provider.Sign(ProofInput{Issuer: "https://api.example.test", EnvironmentID: "env_1", UserID: "usr_1", CLIClientSessionID: "cls_1", JTI: "jti_1", Nonce: "nonce_1", IssuedAt: issuedAt, ExpiresAt: issuedAt.Add(2 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("parts = %d", len(parts))
	}
	var header map[string]any
	var payload map[string]any
	decodeJSONPart(t, parts[0], &header)
	decodeJSONPart(t, parts[1], &payload)
	if header["alg"] != "EdDSA" || header["typ"] != ProofType || header["kid"] != "key-2" {
		t.Fatalf("header = %#v", header)
	}
	if payload["aud"] != "t3-env:env_1" || payload["sub"] != "usr_1" || payload["clientSessionId"] != "cls_1" {
		t.Fatalf("payload = %#v", payload)
	}
	if _, ok := payload["cnf"]; ok {
		t.Fatal("unexpected cnf claim")
	}
	if !ed25519.Verify(testKey(2).Public().(ed25519.PublicKey), []byte(parts[0]+"."+parts[1]), mustDecode(t, parts[2])) {
		t.Fatal("invalid signature")
	}
}

func TestJWKSIncludesRotationOverlapKeys(t *testing.T) {
	provider, err := New([]Key{{ID: "current", PrivateKey: testKey(3)}, {ID: "previous", PrivateKey: testKey(4)}}, "current", 90*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	provider.ServeHTTP(recorder, httptest.NewRequest("GET", "/.well-known/jwks.json", nil))
	if got := recorder.Header().Get("Cache-Control"); got != "public, max-age=90" {
		t.Fatalf("cache-control = %q", got)
	}
	var body struct {
		Keys []map[string]string `json:"keys"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Keys) != 2 {
		t.Fatalf("keys = %d", len(body.Keys))
	}
	ids := map[string]bool{}
	for _, key := range body.Keys {
		ids[key["kid"]] = true
		if key["kty"] != "OKP" || key["crv"] != "Ed25519" || key["alg"] != "EdDSA" || key["use"] != "sig" {
			t.Fatalf("key = %#v", key)
		}
	}
	if !ids["current"] || !ids["previous"] {
		t.Fatalf("ids = %#v", ids)
	}
}

func TestSigningKeyRollbackUsesPublishedOverlapKey(t *testing.T) {
	keys := []Key{{ID: "current", PrivateKey: testKey(7)}, {ID: "previous", PrivateKey: testKey(8)}}
	now := time.Unix(1_700_000_000, 0)
	input := ProofInput{Issuer: "issuer", EnvironmentID: "env", UserID: "user", CLIClientSessionID: "client", JTI: "jti", Nonce: "nonce", IssuedAt: now, ExpiresAt: now.Add(time.Minute)}
	current, err := New(keys, "current", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	rolledBack, err := New(keys, "previous", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	currentToken, _ := current.Sign(input)
	rollbackToken, _ := rolledBack.Sign(input)
	var currentHeader map[string]any
	var rollbackHeader map[string]any
	decodeJSONPart(t, strings.Split(currentToken, ".")[0], &currentHeader)
	decodeJSONPart(t, strings.Split(rollbackToken, ".")[0], &rollbackHeader)
	if currentHeader["kid"] != "current" || rollbackHeader["kid"] != "previous" {
		t.Fatalf("current=%#v rollback=%#v", currentHeader, rollbackHeader)
	}
}

func TestSignRejectsOverlongProof(t *testing.T) {
	provider, _ := New([]Key{{ID: "key", PrivateKey: testKey(5)}}, "key", time.Minute)
	now := time.Now()
	_, err := provider.Sign(ProofInput{Issuer: "issuer", EnvironmentID: "env", UserID: "user", CLIClientSessionID: "client", JTI: "jti", Nonce: "nonce", IssuedAt: now, ExpiresAt: now.Add(MaxProofTTL + time.Second)})
	if err == nil {
		t.Fatal("expected lifetime error")
	}
}

func TestSignCredentialUsesExactClassBindings(t *testing.T) {
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	provider, err := New([]Key{{ID: "key-1", PrivateKey: testKey(1)}}, "key-1", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	token, err := provider.SignCredential(CredentialInput{Issuer: "https://api.example.test", Audience: "paperboat-enrollment", Subject: "env_1", JTI: "jti_enroll_1", IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute), CredentialClass: "helper_enrollment", Scopes: []string{"helper:enroll"}, EnvironmentID: "env_1", EnrollmentID: "enr_1"})
	if err != nil || token == "" {
		t.Fatalf("enrollment credential = %q, %v", token, err)
	}
	claims, err := provider.VerifyCredential(token, "https://api.example.test", "helper_enrollment", now)
	if err != nil || claims.EnrollmentID != "enr_1" || claims.EnvironmentID != "env_1" {
		t.Fatalf("verified claims = %#v, %v", claims, err)
	}
	tampered := token[:len(token)-1] + "A"
	if _, err := provider.VerifyCredential(tampered, "https://api.example.test", "helper_enrollment", now); err == nil {
		t.Fatal("tampered credential accepted")
	}
	if _, err := provider.SignCredential(CredentialInput{Issuer: "https://api.example.test", Audience: "paperboat-enrollment", Subject: "env_1", JTI: "jti_enroll_2", IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute), CredentialClass: "helper_enrollment", Scopes: []string{"helper:connect"}, EnvironmentID: "env_1", EnrollmentID: "enr_1"}); err == nil {
		t.Fatal("broader or wrong scope accepted")
	}
}

func TestPrivateAccessCredentialUsesOnlyProtocolAudiences(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	provider, err := New([]Key{{ID: "private-key", PrivateKey: testKey(21)}}, "private-key", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	input := CredentialInput{
		Issuer: "https://api.example.test", Audience: "paperboat-preview-http", Subject: "acct_1",
		JTI: "nonce_1", IssuedAt: now, ExpiresAt: now.Add(time.Minute), CredentialClass: "private_access",
		Scopes: []string{"private:access"}, EnvironmentID: "paperboat-private-access", AccountID: "acct_1",
		UserID: "user_1", MachineID: "device_1", SessionID: "session_1", ResourceKind: "preview",
		ResourceID: "preview_1", RouteID: "route_1", OperationID: "operation_1", Protocol: "http",
		CarrierSessionID: "carrier_session_1", RouteGeneration: 1, ProcessGeneration: 1, ConfigGeneration: 1,
		InstallationGeneration: 2, SessionGeneration: 3, AssignmentGeneration: 4, EdgeNodeID: "edge_1", EdgeProcessEpoch: "epoch_001",
		Method: "GET", Host: "preview.example.test", Path: "/api", AccessMode: "private", RequestHash: strings.Repeat("a", 64),
		IdempotencyKey: "idem_1", RequestID: "req_001", CorrelationID: "corr_001",
	}
	token, err := provider.SignCredential(input)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := provider.VerifyCredential(token, input.Issuer, input.CredentialClass, now)
	if err != nil || claims.Audience != input.Audience || claims.ResourceID != input.ResourceID || claims.InstallationGeneration != input.InstallationGeneration || claims.SessionGeneration != input.SessionGeneration || claims.AssignmentGeneration != input.AssignmentGeneration || claims.EdgeNodeID != input.EdgeNodeID || claims.EdgeProcessEpoch != input.EdgeProcessEpoch {
		t.Fatalf("private access claims = %#v, %v", claims, err)
	}
	for _, audience := range []string{"paperboat-edge", "paperboat-control", "paperboat-private-access", ""} {
		invalid := input
		invalid.Audience = audience
		if _, err := provider.SignCredential(invalid); err == nil {
			t.Fatalf("audience %q accepted for private access", audience)
		}
	}
}

func TestSignCredentialExecOperationBindsExactOperation(t *testing.T) {
	provider, err := New([]Key{{ID: "key-1", PrivateKey: testKey(1)}}, "key-1", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	input := CredentialInput{Issuer: "https://api.example.test", Audience: "paperboat-machine", Subject: "usr_1", JTI: "jti_exec_1", IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute), CredentialClass: "exec_operation", Scopes: []string{"exec:operate"}, EnvironmentID: "env_1", MachineID: "machine_1", UserID: "usr_1", CLIClientSessionID: "cli_1", OperationID: "operation_exec_1"}
	token, err := provider.SignCredential(input)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := provider.VerifyCredential(token, input.Issuer, "exec_operation", now.Add(time.Minute))
	if err != nil || claims.OperationID != input.OperationID {
		t.Fatalf("claims=%#v err=%v", claims, err)
	}
	input.OperationID = ""
	if _, err := provider.SignCredential(input); err == nil {
		t.Fatal("missing operation binding accepted")
	}
	input.OperationID = "operation_exec_1"
	input.Scopes = []string{"terminal:operate"}
	if _, err := provider.SignCredential(input); err == nil {
		t.Fatal("terminal scope accepted for exec credential")
	}
}

func TestPreviewLaunchCredentialBindsLeaseAndTraceFields(t *testing.T) {
	now := time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)
	provider, err := NewEphemeral(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	input := CredentialInput{
		Issuer: "https://api.example.test", Audience: "paperboat-machine", Subject: "user_1", JTI: "jti_preview_1",
		IssuedAt: now, ExpiresAt: now.Add(2 * time.Minute), CredentialClass: "preview_launch", Scopes: []string{"preview:launch"},
		EnvironmentID: "env_1", AccountID: "acct_1", MachineID: "machine_1", UserID: "user_1", ActorID: "user_1",
		OperationID: "operation_1", PreviewID: "prv_1", OwnerSessionID: "session_1", IdempotencyKey: "create_1",
		RequestID: "request_1", CorrelationID: "correlation_1", TargetScheme: "http", TargetAddress: "127.0.0.1:3000", AccessMode: "public",
		Endpoint: "https://abc.preview.example.test", LeaseDeadline: now.Add(time.Hour), LeaseETag: `"ptv1:preview_lease:cHJ2XzE:1"`,
		State: "allocating", AllocationState: "pending", EdgeState: "pending", OriginState: "unknown", CreatedAt: now, LastRenewedAt: now,
		ExpectedGeneration: 1, RequestHash: strings.Repeat("a", 64),
	}
	token, err := provider.SignCredential(input)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := provider.VerifyCredential(token, input.Issuer, input.CredentialClass, now)
	if err != nil {
		t.Fatal(err)
	}
	if claims.AccountID != input.AccountID || claims.ActorID != input.ActorID || claims.PreviewID != input.PreviewID || claims.OperationID != input.OperationID || claims.OwnerSessionID != input.OwnerSessionID || claims.LeaseETag != input.LeaseETag || claims.ExpectedGeneration != input.ExpectedGeneration || claims.RequestHash != input.RequestHash || claims.IdempotencyKey != input.IdempotencyKey || claims.RequestID != input.RequestID || claims.CorrelationID != input.CorrelationID {
		t.Fatalf("claims = %#v", claims)
	}
	for index, mutate := range []func(*CredentialInput){
		func(value *CredentialInput) { value.IdempotencyKey = "" },
		func(value *CredentialInput) { value.RequestID = "" },
		func(value *CredentialInput) { value.CorrelationID = "" },
		func(value *CredentialInput) { value.RequestHash = strings.Repeat("b", 63) },
		func(value *CredentialInput) { value.ExpectedGeneration = 0 },
	} {
		invalid := input
		mutate(&invalid)
		if _, err := provider.SignCredential(invalid); err == nil {
			t.Fatalf("mutation %d accepted", index)
		}
	}
	if strings.Contains(token, "127.0.0.1:3000") {
		t.Fatal("credential unexpectedly exposed raw target address")
	}
}

func TestSignCredentialSSHOperationIsNotInterchangeable(t *testing.T) {
	provider, err := New([]Key{{ID: "key-1", PrivateKey: testKey(1)}}, "key-1", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	input := CredentialInput{Issuer: "https://api.example.test", Audience: "paperboat-machine", Subject: "usr_1", JTI: "jti_ssh_1", IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute), CredentialClass: "ssh_operation", Scopes: []string{"ssh:operate"}, EnvironmentID: "env_1", MachineID: "machine_1", UserID: "usr_1", CLIClientSessionID: "cli_1", OperationID: "operation_ssh_1"}
	token, err := provider.SignCredential(input)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := provider.VerifyCredential(token, input.Issuer, "ssh_operation", now.Add(time.Minute))
	if err != nil || claims.OperationID != input.OperationID {
		t.Fatalf("claims=%#v err=%v", claims, err)
	}
	if _, err := provider.VerifyCredential(token, input.Issuer, "exec_operation", now.Add(time.Minute)); err == nil {
		t.Fatal("ssh credential accepted as exec credential")
	}
	input.CredentialClass, input.Scopes = "exec_operation", []string{"exec:operate"}
	execToken, err := provider.SignCredential(input)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.VerifyCredential(execToken, input.Issuer, "ssh_operation", now.Add(time.Minute)); err == nil {
		t.Fatal("exec credential accepted as ssh credential")
	}
}

func TestPeerSignalingCredentialBindsExactAttemptAndEndpoints(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	provider, err := New([]Key{{ID: "peer-key", PrivateKey: testKey(13)}}, "peer-key", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	input := CredentialInput{
		Issuer: "https://api.example.test", Audience: "paperboat-edge", Subject: "endpoint_left",
		JTI: "jti_peer_left", IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute),
		CredentialClass: "peer_signaling", Scopes: []string{"peer:signal"}, EnvironmentID: "env_1",
		IntentID: "intent_1", EndpointID: "endpoint_left", PeerEndpointID: "endpoint_right",
		AttemptGeneration: 2, NetworkGeneration: 4, PeerRole: "controlling", EdgeNodeID: "edge_1",
	}
	token, err := provider.SignCredential(input)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := provider.VerifyCredential(token, input.Issuer, "peer_signaling", now)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != input.EndpointID || claims.IntentID != input.IntentID || claims.EndpointID != input.EndpointID || claims.PeerEndpointID != input.PeerEndpointID || claims.AttemptGeneration != 2 || claims.NetworkGeneration != 4 || claims.PeerRole != "controlling" || claims.EdgeNodeID != "edge_1" {
		t.Fatalf("claims=%+v", claims)
	}
	mutations := []func(*CredentialInput){
		func(value *CredentialInput) { value.Scopes = []string{"peer:signal", "connector:admit"} },
		func(value *CredentialInput) { value.PeerEndpointID = value.EndpointID },
		func(value *CredentialInput) { value.AttemptGeneration = 0 },
		func(value *CredentialInput) { value.NetworkGeneration = 0 },
		func(value *CredentialInput) { value.PeerRole = "initiator" },
		func(value *CredentialInput) { value.EdgeNodeID = "" },
		func(value *CredentialInput) { value.ExpiresAt = value.IssuedAt.Add(5*time.Minute + time.Second) },
	}
	for index, mutate := range mutations {
		invalid := input
		mutate(&invalid)
		if _, err := provider.SignCredential(invalid); err == nil {
			t.Fatalf("mutation %d accepted", index)
		}
	}
	if _, err := provider.VerifyCredential(token, input.Issuer, "connector_admission", now); err == nil {
		t.Fatal("peer credential accepted as connector admission")
	}
}

func TestPeerRelayCredentialBindsExactAllocationAndLimits(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	provider, err := New([]Key{{ID: "peer-key", PrivateKey: testKey(14)}}, "peer-key", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	input := CredentialInput{Issuer: "https://api.example.test", Audience: "paperboat-edge", Subject: "intent_1", JTI: "jti_peer_relay_1", IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute), CredentialClass: "peer_relay", Scopes: []string{"peer:relay"}, EnvironmentID: "env_1", IntentID: "intent_1", EdgeNodeID: "edge_1", RouteAllocation: "AAAAAAAAAAAAAAAAAAAAAA", InitiatorEndpointID: "endpoint_left", ResponderEndpointID: "endpoint_right", AttemptGeneration: 2, NetworkGeneration: 4, RouteGeneration: 1, RelayByteLimit: 1 << 30, RelayCarriers: []string{"relay_quic", "relay_wss"}}
	token, err := provider.SignCredential(input)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := provider.VerifyCredential(token, input.Issuer, "peer_relay", now)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != input.IntentID || claims.RouteAllocation != input.RouteAllocation || claims.InitiatorEndpointID != input.InitiatorEndpointID || claims.ResponderEndpointID != input.ResponderEndpointID || claims.RouteGeneration != 1 || claims.RelayByteLimit != 1<<30 || claims.EdgeNodeID != input.EdgeNodeID || !slices.Equal(claims.RelayCarriers, input.RelayCarriers) {
		t.Fatalf("claims=%+v", claims)
	}
	for index, mutate := range []func(*CredentialInput){
		func(value *CredentialInput) { value.Subject = "other_intent" },
		func(value *CredentialInput) { value.RouteAllocation = "not-canonical" },
		func(value *CredentialInput) { value.InitiatorEndpointID = value.ResponderEndpointID },
		func(value *CredentialInput) { value.RouteGeneration = 0 },
		func(value *CredentialInput) { value.RelayByteLimit = 1<<40 + 1 },
		func(value *CredentialInput) { value.EdgeNodeID = "" },
		func(value *CredentialInput) { value.RelayCarriers = nil },
		func(value *CredentialInput) { value.RelayCarriers = []string{"relay_wss", "relay_quic"} },
		func(value *CredentialInput) { value.RelayCarriers = []string{"relay_quic", "relay_http2"} },
		func(value *CredentialInput) { value.RelayCarriers = []string{"relay_quic", "relay_quic"} },
	} {
		invalid := input
		mutate(&invalid)
		if _, err := provider.SignCredential(invalid); err == nil {
			t.Fatalf("mutation %d accepted", index)
		}
	}
}

func TestPeerPMTUCredentialCannotAuthorizeRelay(t *testing.T) {
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	provider, err := New([]Key{{ID: "peer-key", PrivateKey: testKey(14)}}, "peer-key", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	input := CredentialInput{Issuer: "https://api.example.test", Audience: "paperboat-edge", Subject: "intent_1", JTI: "jti_peer_relay_1", IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute), CredentialClass: "peer_pmtu", Scopes: []string{"peer:pmtu"}, EnvironmentID: "env_1", IntentID: "intent_1", EdgeNodeID: "edge_1", RouteAllocation: "AAAAAAAAAAAAAAAAAAAAAA", InitiatorEndpointID: "endpoint_left", ResponderEndpointID: "endpoint_right", AttemptGeneration: 2, NetworkGeneration: 4, RouteGeneration: 1, RelayByteLimit: 1 << 30}
	token, err := provider.SignCredential(input)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.VerifyCredential(token, input.Issuer, "peer_pmtu", now); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.VerifyCredential(token, input.Issuer, "peer_relay", now); err == nil {
		t.Fatal("PMTU credential authorized relay access")
	}
}

func TestVerifyCredentialExpiryGraceIsExplicitAndBounded(t *testing.T) {
	now := time.Date(2026, 7, 25, 12, 0, 0, 0, time.UTC)
	provider, err := New([]Key{{ID: "key-1", PrivateKey: testKey(1)}}, "key-1", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	token, err := provider.SignCredential(CredentialInput{Issuer: "https://api.example.test", Audience: "paperboat-control", Subject: "helper_1", JTI: "jti_identity_1", IssuedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour), CredentialClass: "helper_identity", Scopes: []string{"helper:connect", "helper:renew"}, EnvironmentID: "env_1", HelperID: "helper_1", MachineID: "machine_1", KeyThumbprint: "sha256:key"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.VerifyCredential(token, "https://api.example.test", "helper_identity", now); err == nil {
		t.Fatal("strict verification accepted expired credential")
	}
	if _, err := provider.VerifyCredentialWithExpiryGrace(token, "https://api.example.test", "helper_identity", now, 2*time.Hour); err != nil {
		t.Fatalf("grace verification rejected credential: %v", err)
	}
	if _, err := provider.VerifyCredentialWithExpiryGrace(token, "https://api.example.test", "helper_identity", now, 30*time.Minute); err == nil {
		t.Fatal("grace verification accepted credential outside grace")
	}
}

func TestMachineControlCredentialRequiresAllMachineBindings(t *testing.T) {
	provider, err := NewEphemeral(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)
	input := CredentialInput{Issuer: "https://api.example.test", Audience: "paperboat-control", Subject: "mch_1", JTI: "mcc_1", IssuedAt: now, ExpiresAt: now.Add(time.Hour), CredentialClass: "machine_control", Scopes: []string{"machine:connect", "machine:renew"}, EnvironmentID: "env_1", MachineID: "mch_1", UserID: "usr_1", KeyThumbprint: "sha256:key", InstallationGeneration: 2, SessionGeneration: 3}
	token, err := provider.SignCredential(input)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := provider.VerifyCredential(token, input.Issuer, "machine_control", now)
	if err != nil || claims.UserID != input.UserID || claims.MachineID != input.MachineID || claims.InstallationGeneration != 2 {
		t.Fatalf("claims=%+v err=%v", claims, err)
	}
	input.InstallationGeneration = 0
	if _, err := provider.SignCredential(input); err == nil {
		t.Fatal("credential without installation generation was accepted")
	}
	input.InstallationGeneration, input.SessionGeneration = 2, 0
	if _, err := provider.SignCredential(input); err == nil {
		t.Fatal("credential without session generation was accepted")
	}
}

func TestSignCredentialConfigSyncBindsAssignmentAndWarning(t *testing.T) {
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	provider, err := New([]Key{{ID: "key-config", PrivateKey: testKey(11)}}, "key-config", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	token, err := provider.SignCredential(CredentialInput{Issuer: "https://api.example.test", Audience: "paperboat-machine", Subject: "machine_1", JTI: "jti_config_1", IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute), CredentialClass: "config_sync", Scopes: []string{"config:pull", "config:apply", "config:report"}, EnvironmentID: "env_1", MachineID: "machine_1", InstallationGeneration: 2, AssignmentID: "assignment_1", WarningRevision: "warning_7"})
	if err != nil {
		t.Fatal(err)
	}
	claims, err := provider.VerifyCredential(token, "https://api.example.test", "config_sync", now)
	if err != nil || claims.AssignmentID != "assignment_1" || claims.WarningRevision != "warning_7" || claims.MachineID != "machine_1" || claims.InstallationGeneration != 2 {
		t.Fatalf("claims = %#v, %v", claims, err)
	}
	if _, err := provider.SignCredential(CredentialInput{Issuer: "https://api.example.test", Audience: "paperboat-machine", Subject: "machine_1", JTI: "jti_config_2", IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute), CredentialClass: "config_sync", Scopes: []string{"config:pull"}, EnvironmentID: "env_1", MachineID: "machine_1", InstallationGeneration: 2, AssignmentID: "assignment_1", WarningRevision: "warning_7"}); err == nil {
		t.Fatal("incomplete config scopes accepted")
	}
}

func TestSignTerminalControlBindsOperationAndTerminalIDs(t *testing.T) {
	provider, _ := New([]Key{{ID: "key", PrivateKey: testKey(9)}}, "key", time.Minute)
	now := time.Unix(1_700_000_000, 0)
	token, err := provider.SignTerminalControl(TerminalControlInput{Issuer: "https://api.example", EnvironmentID: "env_1", UserID: "usr_1", JTI: "jti_1", Nonce: "nonce_1", IssuedAt: now, ExpiresAt: now.Add(time.Minute), Operation: "delete_history", ThreadID: "paperboat", TerminalIDs: []string{"term_a", "term_b"}})
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")
	var header, payload map[string]any
	decodeJSONPart(t, parts[0], &header)
	decodeJSONPart(t, parts[1], &payload)
	if header["typ"] != TerminalControlType || payload["scope"].([]any)[0] != TerminalControlScope || payload["operation"] != "delete_history" || payload["threadId"] != "paperboat" {
		t.Fatalf("header=%#v payload=%#v", header, payload)
	}
	if got := payload["terminalIds"].([]any); len(got) != 2 || got[0] != "term_a" {
		t.Fatalf("terminal IDs=%#v", got)
	}
}

func TestSignRevocationUsesSeparateTypeAndScope(t *testing.T) {
	provider, _ := New([]Key{{ID: "key", PrivateKey: testKey(6)}}, "key", time.Minute)
	now := time.Unix(1_700_000_000, 0)
	token, err := provider.SignRevocation(RevocationInput{
		ProofInput: ProofInput{Issuer: "issuer", EnvironmentID: "env", UserID: "user", CLIClientSessionID: "client", JTI: "jti", Nonce: "nonce", IssuedAt: now, ExpiresAt: now.Add(time.Minute)},
		SessionIDs: []string{"session-1"}, Reason: "logout",
	})
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")
	var header map[string]any
	var payload map[string]any
	decodeJSONPart(t, parts[0], &header)
	decodeJSONPart(t, parts[1], &payload)
	if header["typ"] != RevokeType || payload["reason"] != "logout" {
		t.Fatalf("header=%#v payload=%#v", header, payload)
	}
	if scope := payload["scope"].([]any); len(scope) != 1 || scope[0] != RevokeScope {
		t.Fatalf("scope=%#v", scope)
	}
}

func TestSignHealthUsesDedicatedTypeAndScope(t *testing.T) {
	provider, _ := New([]Key{{ID: "health-key", PrivateKey: testKey(9)}}, "health-key", time.Minute)
	now := time.Unix(1_700_000_000, 0)
	token, err := provider.SignHealth(ProofInput{
		Issuer: "https://paperboat.example", EnvironmentID: "env_1", UserID: "usr_1",
		CLIClientSessionID: "cls_1", JTI: "health-jti", Nonce: "health-nonce",
		IssuedAt: now, ExpiresAt: now.Add(time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")
	var header map[string]any
	var payload map[string]any
	decodeJSONPart(t, parts[0], &header)
	decodeJSONPart(t, parts[1], &payload)
	if header["typ"] != HealthType || header["kid"] != "health-key" {
		t.Fatalf("header=%#v", header)
	}
	if payload["aud"] != "t3-env:env_1" || payload["sub"] != "usr_1" || payload["environmentId"] != "env_1" || payload["clientSessionId"] != "cls_1" {
		t.Fatalf("payload=%#v", payload)
	}
	if scope := payload["scope"].([]any); len(scope) != 1 || scope[0] != HealthScope {
		t.Fatalf("scope=%#v", scope)
	}
}

func TestFileTransferCredentialIsSessionAndClientBound(t *testing.T) {
	provider, _ := New([]Key{{ID: "transfer-key", PrivateKey: testKey(10)}}, "transfer-key", time.Minute)
	now := time.Unix(1_700_000_000, 0)
	input := CredentialInput{Issuer: "https://api.example.test", Audience: "paperboat-machine", Subject: "usr_1", JTI: "jti_transfer_1", IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute), CredentialClass: "file_transfer", Scopes: []string{"file:transfer"}, EnvironmentID: "env_1", MachineID: "machine_1", SourceMachineID: "machine_source", UserID: "usr_1", CLIClientSessionID: "cli_1", SessionID: "ses_1"}
	token, err := provider.SignCredential(input)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := provider.VerifyCredential(token, input.Issuer, "file_transfer", now)
	if err != nil {
		t.Fatal(err)
	}
	if claims.CLIClientSessionID != "cli_1" || claims.SessionID != "ses_1" || len(claims.Scopes) != 1 || claims.Scopes[0] != "file:transfer" {
		t.Fatalf("claims=%#v", claims)
	}
	input.Scopes = []string{"file:stage"}
	if _, err := provider.SignCredential(input); err == nil {
		t.Fatal("accepted legacy scope")
	}
}

func TestFileTransferCredentialAllowsNoTerminalSession(t *testing.T) {
	now := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	provider, err := New([]Key{{ID: "transfer-key", PrivateKey: testKey(11)}}, "transfer-key", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	input := CredentialInput{Issuer: "https://api.example.test", Audience: "paperboat-machine", Subject: "usr_1", JTI: "jti_transfer_2", IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute), CredentialClass: "file_transfer", Scopes: []string{"file:transfer"}, EnvironmentID: "env_1", MachineID: "machine_1", SourceMachineID: "machine_source", UserID: "usr_1", CLIClientSessionID: "cli_1"}
	token, err := provider.SignCredential(input)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := provider.VerifyCredential(token, input.Issuer, "file_transfer", now)
	if err != nil {
		t.Fatal(err)
	}
	if claims.SessionID != "" || claims.SourceMachineID != input.SourceMachineID {
		t.Fatalf("claims=%+v", claims)
	}
}

func decodeJSONPart(t *testing.T, part string, target any) {
	t.Helper()
	if err := json.Unmarshal(mustDecode(t, part), target); err != nil {
		t.Fatal(err)
	}
}
func mustDecode(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}
