package httpapi

import (
	"context"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/auth"
	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/peeridentity"
	"github.com/pinksaucepasta/paperboat-server/internal/peersessions"
)

// configureInspectorNativeAuthority adds the production device, endpoint identity,
// machine and signed peer-network APIs to the linked private fixture. The client
// creates its own endpoint key custody and registers certificates over those APIs.
func configureInspectorNativeAuthority(t *testing.T, database *db.DB, linked *inspectorLinkedAuthority, issuer string, opts *Options) {
	t.Helper()
	cfg := config.Default().CLIAuth
	cfg.AccessTokenLifetime = time.Hour
	devices := auth.NewDeviceService(database, audit.NewWriter(database), cfg, []string{"inspector-native-fixture-device-hash"})
	authorization, err := devices.Authorize(t.Context(), auth.DeviceAuthorizationInput{ClientID: cfg.ClientID, ClientLabel: "Inspector linked CLI", DeviceType: "desktop", OS: "linux", Scopes: cfg.AllowedScopes, Network: "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = devices.Decide(t.Context(), authorization.UserCode, linked.Descriptor["OwnerAccountID"].(string), true); err != nil {
		t.Fatal(err)
	}
	token, err := devices.Poll(t.Context(), auth.DeviceTokenInput{ClientID: cfg.ClientID, DeviceCode: authorization.DeviceCode, Network: "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	repo, err := peeridentity.NewSQLRepository(database, audit.NewWriter(database))
	if err != nil {
		t.Fatal(err)
	}
	identity, err := peeridentity.NewService(repo)
	if err != nil {
		t.Fatal(err)
	}
	network, err := peersessions.NewNetworkService(database, linked.Signer, issuer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = database.SQL().ExecContext(t.Context(), `INSERT INTO paperboat.control_environments(id,workspace_id,owner_user_id) VALUES($1,$2,$3) ON CONFLICT(id) DO NOTHING`, linked.Descriptor["EnvironmentID"], "inspector-native-fixture", linked.Descriptor["OwnerAccountID"]); err != nil {
		t.Fatal(err)
	}

	relayAddress := os.Getenv("PAPERBOAT_INSPECTOR_FIXTURE_RELAY_ADDRESS")
	if relayAddress == "" {
		relayAddress = "127.0.0.1:31325"
	}
	host, portText, err := net.SplitHostPort(relayAddress)
	if err != nil || !net.ParseIP(host).IsLoopback() {
		t.Fatal("native fixture relay must be loopback")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		t.Fatal("invalid native fixture relay port")
	}
	node := linked.Descriptor["EdgeNodeID"].(string) + "-native"
	epoch := linked.Descriptor["EdgeProcessEpoch"].(string) + "-native"
	if _, err = database.SQL().ExecContext(t.Context(), `INSERT INTO paperboat.control_tunnel_nodes(id,edge_pool,protocol_version,process_epoch,endpoint_host,endpoint_tcp_port,endpoint_quic_port,state,ready,last_heartbeat_at,node_generation,region,failure_domain,roles,transports,capacity_limit,capacity_used,capacity_observed_at,registry_expires_at,allowed_account_ids) VALUES($1,'inspector-native','v1',$2,$3,443,$4,'ready',true,now(),1,'test','fixture',ARRAY['relay'],ARRAY['derp_quic'],100,0,now(),now()+interval '1 hour',ARRAY[$5])`, node, epoch, host, port, linked.Descriptor["OwnerAccountID"]); err != nil {
		t.Fatal(err)
	}
	life, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		tick := time.NewTicker(5 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-life.Done():
				return
			case <-tick.C:
				_, _ = database.SQL().ExecContext(life, `UPDATE paperboat.control_tunnel_nodes SET last_heartbeat_at=now(),capacity_observed_at=now() WHERE id=$1`, node)
			}
		}
	}()
	t.Cleanup(func() {
		cancel()
		<-done
		_, _ = database.SQL().ExecContext(context.Background(), `DELETE FROM paperboat.control_tunnel_nodes WHERE id=$1`, node)
	})
	linked.Descriptor["RelayNodeID"] = node
	linked.Descriptor["RelayProcessEpoch"] = epoch
	linked.Descriptor["RelayAddress"] = relayAddress

	opts.DeviceAuth = devices
	opts.PeerIdentity = identity
	opts.PeerNetwork = network
	opts.MintKeys = linked.Signer
	opts.RuntimeIdentity = linked.Enrollment
	opts.Enrollment = linked.Enrollment
	linked.Descriptor["CLIAccessToken"] = token.AccessToken
	linked.Descriptor["CLIRefreshToken"] = token.RefreshToken
	linked.Descriptor["CLIClientSessionID"] = token.CLIClientSessionID
	linked.Descriptor["CLITokenExpiresAt"] = time.Now().UTC().Add(time.Duration(token.ExpiresIn) * time.Second)
	linked.Descriptor["NetworkIssuer"] = issuer
}
