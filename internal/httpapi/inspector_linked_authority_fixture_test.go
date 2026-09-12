package httpapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/auth"
	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/controlplane"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/inspectaccess"
	"github.com/pinksaucepasta/paperboat-server/internal/mint"
	"github.com/pinksaucepasta/paperboat-server/internal/previewattachment"
)

type inspectorLinkedAuthority struct {
	Signer          *mint.Provider
	Enrollment      *controlplane.EnrollmentService
	MachineVerifier previewattachment.MachineProofVerifier
	EdgeService     *controlplane.EdgeService
	TLSConfig       *tls.Config
	Descriptor      map[string]any
}

// newInspectorLinkedAuthority extends the browser fixture with actual renewable
// machine credentials, node authentication and live carrier assignment rows.
// Private material is returned only for the caller's 0600 fixture descriptor.
func newInspectorLinkedAuthority(t *testing.T, database *db.DB, now time.Time, suffix, owner, lease, tunnel, route, node string) *inspectorLinkedAuthority {
	t.Helper()
	ctx := context.Background()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := database.SQL().ExecContext(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	machine, environment, epoch := "mch_ih_"+suffix, "env_ih_"+suffix, "epoch-ih-"+suffix
	seed := sha256.Sum256([]byte("inspector-http-key:" + suffix))
	private := ed25519.NewKeyFromSeed(seed[:])
	public := private.Public().(ed25519.PublicKey)
	thumb := sha256.Sum256(public)
	origin := os.Getenv("PAPERBOAT_INSPECTOR_FIXTURE_ORIGIN_ADDRESS")
	if origin == "" {
		origin = "127.0.0.1:31323"
	}
	host, _, err := net.SplitHostPort(origin)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		t.Fatal("linked origin must be literal loopback")
	}
	exec(`UPDATE paperboat.preview_leases SET target_address=$1 WHERE id=$2`, origin, lease)
	exec(`UPDATE paperboat.preview_lease_carrier_attachments SET expires_at=$1 WHERE preview_id=$2`, now.Add(time.Hour), lease)
	exec(`UPDATE paperboat.tunnel_routes SET origin_address=$1 WHERE id=$2`, origin, route)
	exec(`UPDATE paperboat.tunnels SET created_by_host_id=$1 WHERE id=$2`, machine, tunnel)
	exec(`UPDATE paperboat.control_tunnel_nodes SET registry_expires_at=$1,region='test',failure_domain='test',roles=ARRAY['edge'],transports=ARRAY['http3','http2'],capacity_limit=10,capacity_observed_at=now() WHERE id=$2`, now.Add(time.Hour), node)
	operation, jti := "mc_ir_"+suffix, "mcc_ir_"+suffix
	exec(`INSERT INTO paperboat.machine_control_renewals(operation_id,machine_id,installation_generation,credential_jti,issued_at,expires_at,session_generation) VALUES($1,$2,1,$3,$4,$5,1)`, operation, machine, jti, now, now.Add(time.Hour))
	exec(`INSERT INTO paperboat.machine_control_sessions(machine_id,installation_generation,session_generation,operation_id,credential_jti,issued_at,expires_at) VALUES($1,1,1,$2,$3,$4,$5)`, machine, operation, jti, now, now.Add(time.Hour))
	signer, err := mint.NewEphemeral(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	issuer := "https://inspector-linked.test"
	token, err := signer.SignCredential(mint.CredentialInput{Issuer: issuer, Audience: "paperboat-control", Subject: machine, JTI: jti, IssuedAt: now, ExpiresAt: now.Add(time.Hour), CredentialClass: "machine_control", Scopes: []string{"machine:connect", "machine:renew"}, EnvironmentID: environment, MachineID: machine, UserID: owner, KeyThumbprint: "sha256:" + base64.RawURLEncoding.EncodeToString(thumb[:]), InstallationGeneration: 1, SessionGeneration: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = signer.VerifyCredential(token, issuer, "machine_control", time.Now().UTC()); err != nil {
		t.Fatalf("minted machine credential self-check: %v", err)
	}
	enrollment := controlplane.NewEnrollmentService(database, signer, audit.NewWriter(database), issuer, "")
	verifier, err := NewPreviewAttachmentMachineProofVerifier(enrollment)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte(`{}`))
	connector, session, assignment := "con_link_"+suffix, "ses_link_"+suffix, "asg_link_"+suffix
	exec(`INSERT INTO paperboat.tunnel_config_generations(tunnel_id,generation,content_hash,snapshot,activation_state,created_by_actor_id,activated_at,retained_until) VALUES($1,1,$2,$3,'active',$4,now(),now()+interval '1 hour')`, tunnel, hash[:], []byte(`{}`), owner)
	exec(`INSERT INTO paperboat.tunnel_connectors(id,tunnel_id,host_id,credential_reference,credential_thumbprint,protocol_version,last_session_id,last_applied_config_generation) VALUES($1,$2,$3,$4,$4,'1.0',$5,1)`, connector, tunnel, machine, "ref_link_"+suffix, session)
	exec(`INSERT INTO paperboat.tunnel_connector_sessions(id,connector_id,process_generation,protocol_version,state,lease_deadline,retained_until,applied_config_generation) VALUES($1,$2,1,'1.0','ready',now()+interval '1 hour',now()+interval '1 hour',1)`, session, connector)
	exec(`INSERT INTO paperboat.tunnel_edge_route_assignments(assignment_id,route_id,assignment_generation,account_id,tunnel_id,connector_id,host_id,machine_identity_public_key,machine_identity_thumbprint,connector_generation,connector_session_id,connector_process_generation,config_generation,config_content_hash,access_mode,route_generation,route_revision,edge_node_id,edge_process_epoch,edge_failure_domain,state,observed_state) VALUES($1,$2,1,$3,$4,$5,$6,$7,$8,1,$9,1,1,$10,'team',7,7,$11,$12,'test','active','ready')`, assignment, route, owner, tunnel, connector, machine, base64.RawURLEncoding.EncodeToString(public), base64.RawURLEncoding.EncodeToString(thumb[:]), session, hash[:], node, epoch)
	var previewEndpoint, tunnelEndpoint string
	if err = database.SQL().QueryRowContext(ctx, `SELECT p.endpoint,t.stable_endpoint FROM paperboat.preview_leases p CROSS JOIN paperboat.tunnels t WHERE p.id=$1 AND t.id=$2`, lease, tunnel).Scan(&previewEndpoint, &tunnelEndpoint); err != nil {
		t.Fatal(err)
	}
	previewURL, _ := url.Parse(previewEndpoint)
	tunnelURL, _ := url.Parse(tunnelEndpoint)
	tlsPublic, tlsPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	certTemplate := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "Paperboat linked inspector test"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, IsCA: true, BasicConstraintsValid: true, DNSNames: []string{"localhost", "edge.example.test", previewURL.Hostname(), tunnelURL.Hostname()}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}}
	certDER, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, tlsPublic, tlsPrivate)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(tlsPrivate)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	tlsPair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(certDER)
	spki := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	pin := fmt.Sprintf("sha256:%x", spki)
	exec(`UPDATE paperboat.control_tunnel_nodes SET carrier_server_spki_sha256=$1,carrier_server_certificate_chain_pem=$2 WHERE id=$3`, pin, string(certPEM), node)
	exec(`UPDATE paperboat.preview_lease_carrier_attachments SET edge_carrier_server_spki_sha256=$1,edge_carrier_server_certificate_chain_pem=$2 WHERE preview_id=$3`, pin, string(certPEM), lease)
	edgeSecret := make([]byte, 32)
	if _, err = rand.Read(edgeSecret); err != nil {
		t.Fatal(err)
	}
	edgeCredential := base64.RawURLEncoding.EncodeToString(edgeSecret)
	service := inspectaccess.NewService(database)
	access := func(kind, resource, routeID string) inspectaccess.AccessResult {
		t.Helper()
		credential, e := service.Issue(ctx, inspectaccess.IssueRequest{AccountID: owner, ResourceKind: kind, ResourceID: resource, RouteID: routeID, Action: "inspect", TTL: time.Minute})
		if e != nil {
			t.Fatal(e)
		}
		out, e := service.ResolveAccess(ctx, inspectaccess.AccessRequest{AccountID: owner, Token: credential.Token, ResourceKind: kind, ResourceID: resource, RouteID: routeID, Action: "inspect", Transport: "edge"})
		if e != nil {
			t.Fatal(e)
		}
		if e = service.RevokeCredential(ctx, owner, credential.CredentialID); e != nil {
			t.Fatal(e)
		}
		return out
	}
	previewAccess, tunnelAccess := access("preview", lease, lease), access("tunnel", tunnel, route)
	lifetime, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		tick := time.NewTicker(5 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-lifetime.Done():
				return
			case <-tick.C:
				_, _ = database.SQL().ExecContext(lifetime, `UPDATE paperboat.tunnel_connector_sessions SET last_heartbeat_at=now() WHERE id=$1`, session)
				_, _ = database.SQL().ExecContext(lifetime, `UPDATE paperboat.control_tunnel_nodes SET last_heartbeat_at=now(),capacity_observed_at=now() WHERE id=$1`, node)
			}
		}
	}()
	t.Cleanup(func() {
		cancel()
		<-done
		_, _ = database.SQL().ExecContext(context.Background(), `DELETE FROM paperboat.tunnel_edge_route_assignments WHERE assignment_id=$1`, assignment)
		_, _ = database.SQL().ExecContext(context.Background(), `DELETE FROM paperboat.machine_control_sessions WHERE machine_id=$1`, machine)
		_, _ = database.SQL().ExecContext(context.Background(), `DELETE FROM paperboat.machine_control_renewals WHERE machine_id=$1`, machine)
	})
	return &inspectorLinkedAuthority{Signer: signer, Enrollment: enrollment, MachineVerifier: verifier, EdgeService: controlplane.NewEdgeService(database, edgeCredential), TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{tlsPair}}, Descriptor: map[string]any{"FixtureExpiresAt": now.Add(time.Hour), "OwnerAccountID": owner, "MachineID": machine, "EnvironmentID": environment, "MachineGeneration": 1, "MachineToken": token, "MachinePrivateKey": base64.RawURLEncoding.EncodeToString(private), "MachinePublicKey": base64.RawURLEncoding.EncodeToString(public), "MachineThumbprint": base64.RawURLEncoding.EncodeToString(thumb[:]), "EdgeNodeID": node, "EdgeProcessEpoch": epoch, "EdgeCredential": edgeCredential, "TLSCertificatePEM": string(certPEM), "TLSPrivateKeyPEM": string(keyPEM), "OriginAddress": origin, "PreviewAccess": previewAccess, "TunnelAccess": tunnelAccess, "PreviewCarrier": previewAccess.Carrier, "TunnelCarrier": tunnelAccess.Carrier, "PreviewEndpoint": previewEndpoint, "TunnelEndpoint": tunnelEndpoint}}
}

func TestInspectorLinkedAuthorityProductionPostgres(t *testing.T) {
	dsn := os.Getenv("PAPERBOAT_TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN")
	}
	if err := db.ValidateIsolatedTestDSN(dsn, os.Getenv("PAPERBOAT_DATABASE_DSN")); err != nil {
		t.Fatal(err)
	}
	database, err := db.Open(config.Database{Driver: "postgres", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	now := time.Now().UTC()
	suffix := fmt.Sprint(now.UnixNano())
	owner, _, lease, tunnel, route, node := inspectorHTTPFixture(t, t.Context(), database, now, suffix)
	linked := newInspectorLinkedAuthority(t, database, now, suffix, owner, lease, tunnel, route, node)
	authService := auth.NewService(database, audit.NewWriter(database), auth.FakeWorkOSVerifier{}, []string{"inspector-linked-session-key"}, true, "https://login.pprbt.dev")
	opts := Options{Config: config.Default(), Auth: authService, EdgeControl: linked.EdgeService.Handler(), Inspector: &InspectorHandlers{Access: inspectaccess.NewService(database), Machine: linked.MachineVerifier}}
	configureInspectorNativeAuthority(t, database, linked, "https://inspector-linked.test", &opts)
	router := NewRouter(opts)
	server := httptest.NewUnstartedServer(router)
	server.TLS = linked.TLSConfig
	server.StartTLS()
	t.Cleanup(server.Close)
	grant, err := inspectaccess.NewService(database).Issue(t.Context(), inspectaccess.IssueRequest{AccountID: owner, ResourceKind: "preview", ResourceID: lease, RouteID: lease, Action: "inspect", TTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{"credential_token": grant.Token, "resource_kind": "preview", "resource_id": lease, "route_id": lease, "action": "inspect"})
	digest := sha256.Sum256(body)
	issued := time.Now().UTC()
	proofBody, _ := json.Marshal(map[string]any{"machine_id": linked.Descriptor["MachineID"], "environment_id": linked.Descriptor["EnvironmentID"], "installation_generation": 1, "operation_id": "inspector-proof-" + suffix, "method": "POST", "path": "/v1/inspector/authorize", "body_sha256": base64.RawURLEncoding.EncodeToString(digest[:]), "issued_at": issued, "expires_at": issued.Add(time.Minute)})
	private, _ := base64.RawURLEncoding.DecodeString(linked.Descriptor["MachinePrivateKey"].(string))
	proof, _ := json.Marshal(map[string]string{"alg": "EdDSA", "payload": base64.RawURLEncoding.EncodeToString(proofBody), "signature": base64.RawURLEncoding.EncodeToString(ed25519.Sign(ed25519.PrivateKey(private), proofBody))})
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/v1/inspector/authorize", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+linked.Descriptor["MachineToken"].(string))
	req.Header.Set("X-Paperboat-Machine-Identity", linked.Descriptor["MachineToken"].(string))
	req.Header.Set("X-Paperboat-Machine-Proof", base64.RawURLEncoding.EncodeToString(proof))
	response, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("production machine-proof inspector authorization status=%d", response.StatusCode)
	}
	edgeBody, _ := json.Marshal(map[string]string{"credential_token": grant.Token, "resource_kind": "preview", "resource_id": lease, "route_id": lease, "action": "inspect", "edge_node_id": node, "process_epoch": "epoch-ih-" + suffix})
	for _, allowed := range []bool{true, false} {
		req, _ := http.NewRequest(http.MethodPost, server.URL+"/v1/edge/inspector/access", bytes.NewReader(edgeBody))
		req.Header.Set("Content-Type", "application/json")
		secret := linked.Descriptor["EdgeCredential"].(string)
		if !allowed {
			secret = "denied"
		}
		req.Header.Set("Authorization", "Bearer "+secret)
		req.Header.Set("X-Paperboat-Edge-Node-ID", node)
		req.Header.Set("X-Paperboat-Edge-Process-Epoch", "epoch-ih-"+suffix)
		response, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		response.Body.Close()
		want := http.StatusOK
		if !allowed {
			want = http.StatusUnauthorized
		}
		if response.StatusCode != want {
			t.Fatalf("production edge auth allowed=%v status=%d", allowed, response.StatusCode)
		}
	}
}
