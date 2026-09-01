package connectorprotocol

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
)

// TestLiveCarrierBootstrapDescriptor is a read-only opt-in acceptance check.
// It exercises the exact production descriptor query and validation against a
// deployed database without mutating sessions, routes, or node state.
func TestLiveCarrierBootstrapDescriptor(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("PAPERBOAT_LIVE_DATABASE_DSN"))
	connectorID := strings.TrimSpace(os.Getenv("PAPERBOAT_LIVE_CONNECTOR_ID"))
	if dsn == "" || connectorID == "" {
		t.Skip("set PAPERBOAT_LIVE_DATABASE_DSN and PAPERBOAT_LIVE_CONNECTOR_ID")
	}
	store, err := db.Open(config.Database{Driver: "postgres", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	ctx := context.Background()
	var active ActiveControlSession
	var publicKey []byte
	var hash []byte
	err = store.SQL().QueryRowContext(ctx, `
		SELECT t.account_id, c.tunnel_id, c.id, c.host_id,
		       s.id, s.process_generation, s.credential_generation,
		       s.applied_config_generation, g.content_hash, cg.verifier_public_key
		FROM tunnel_connectors c
		JOIN tunnels t ON t.id = c.tunnel_id
		JOIN tunnel_connector_sessions s ON s.connector_id = c.id
		JOIN tunnel_config_generations g
		  ON g.tunnel_id = c.tunnel_id
		 AND g.generation = s.applied_config_generation
		JOIN tunnel_connector_credential_generations cg
		  ON cg.connector_id = c.id
		 AND cg.generation = s.credential_generation
		WHERE c.id = $1
		ORDER BY s.process_generation DESC
		LIMIT 1`, connectorID).Scan(
		&active.AccountID, &active.TunnelID, &active.ConnectorID, &active.HostID,
		&active.SessionID, &active.ProcessGeneration, &active.CredentialGeneration,
		&active.ConfigGeneration, &hash, &publicKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	active.ConfigContentHash = "sha256:" + hex.EncodeToString(hash)
	active.IdentityKeyThumbprint, err = IdentityThumbprint(ed25519.PublicKey(publicKey))
	if err != nil {
		t.Fatal(err)
	}
	active.IdentityKeyID, err = IdentityKeyID(ed25519.PublicKey(publicKey))
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := (SQLCarrierBootstrapSource{DB: store}).Descriptor(ctx, active)
	if err != nil {
		t.Fatalf("production descriptor: %v", err)
	}
	if descriptor.Validate(time.Now().UTC()) != nil || len(descriptor.Carriers) == 0 {
		t.Fatalf("invalid descriptor: %+v", descriptor)
	}
}

// TestLiveConnectorHeartbeatPersistence exercises the same durable heartbeat
// transition used by a live control stream. Run it only while the selected
// connector's latest session is ready.
func TestLiveConnectorHeartbeatPersistence(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("PAPERBOAT_LIVE_DATABASE_DSN"))
	connectorID := strings.TrimSpace(os.Getenv("PAPERBOAT_LIVE_CONNECTOR_ID"))
	if dsn == "" || connectorID == "" {
		t.Skip("set PAPERBOAT_LIVE_DATABASE_DSN and PAPERBOAT_LIVE_CONNECTOR_ID")
	}
	store, err := db.Open(config.Database{Driver: "postgres", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	ctx := context.Background()
	var ref SessionRef
	var accountID, state string
	var generation int64
	var hash []byte
	err = store.SQL().QueryRowContext(ctx, `
		SELECT t.account_id, c.tunnel_id, c.id, s.id, s.process_generation,
		       s.applied_config_generation, g.content_hash, s.state
		FROM tunnel_connectors c
		JOIN tunnels t ON t.id = c.tunnel_id
		JOIN tunnel_connector_sessions s ON s.connector_id = c.id
		JOIN tunnel_config_generations g
		  ON g.tunnel_id = c.tunnel_id
		 AND g.generation = s.applied_config_generation
		WHERE c.id = $1
		ORDER BY s.process_generation DESC
		LIMIT 1`, connectorID).Scan(&accountID, &ref.TunnelID, &ref.ConnectorID, &ref.SessionID, &ref.ProcessGeneration, &generation, &hash, &state)
	if err != nil {
		t.Fatal(err)
	}
	if state != "ready" {
		t.Fatalf("latest session state=%s, want ready", state)
	}
	now := time.Now().UTC()
	contentHash := "sha256:" + hex.EncodeToString(hash)
	heartbeat := Heartbeat{AccountID: accountID, SessionID: ref.SessionID, TunnelID: ref.TunnelID, ConnectorID: ref.ConnectorID, ProcessGeneration: ref.ProcessGeneration, LastAppliedGeneration: uint64(generation), LastAppliedHash: contentHash, SentAt: now}
	ack := HeartbeatAck{AccountID: accountID, TunnelID: ref.TunnelID, ConnectorID: ref.ConnectorID, SessionID: ref.SessionID, ProcessGeneration: ref.ProcessGeneration, ServerTime: now, LeaseExpiresAt: now.Add(DefaultLease)}
	controlStore, err := NewSQLControlStore(store, SQLControlStoreConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if err := controlStore.RecordHeartbeat(ctx, ref, heartbeat, ack); err != nil {
		t.Fatalf("record production heartbeat: %v", err)
	}
}
