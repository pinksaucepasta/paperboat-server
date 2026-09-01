package db_test

import (
	"bytes"
	"context"
	"database/sql"
	"embed"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/connectorprotocol"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pressly/goose/v3"
)

// Keep this opt-in test external to the db package so it can compare the
// migrated bytes with connectorprotocol.NewSnapshot without creating an
// import cycle (connectorprotocol uses the database package).
//
//go:embed migrations/*.sql
var snapshotMigrationsFS embed.FS

const snapshotMigrationsDir = "migrations"

// TestTunnelConfigSnapshotBytesMigrationUpDownUp is intentionally guarded by a
// second environment flag because it rolls the shared test database back one
// migration. Run it only against an isolated PostgreSQL database.
func TestTunnelConfigSnapshotBytesMigrationUpDownUp(t *testing.T) {
	dsn := os.Getenv("PAPERBOAT_TEST_DATABASE_DSN")
	if dsn == "" || os.Getenv("PAPERBOAT_TEST_MIGRATION_ROLLBACK") != "1" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN and PAPERBOAT_TEST_MIGRATION_ROLLBACK=1 on an isolated database")
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
	if err := db.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	configureGooseForSnapshotMigration(t)
	rolledBack := false
	t.Cleanup(func() {
		if !rolledBack {
			return
		}
		if err := goose.UpContext(context.Background(), database.SQL(), snapshotMigrationsDir); err != nil {
			t.Errorf("restore snapshot byte migration after failed test: %v", err)
		}
	})

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	accountID := "usr_snapshot_bytes_" + suffix
	tunnelID := "tun_snapshot_bytes_" + suffix
	defer func() {
		_, _ = database.SQL().ExecContext(ctx, `DELETE FROM paperboat.users WHERE id=$1`, accountID)
	}()
	if _, err := database.SQL().ExecContext(ctx, `
INSERT INTO paperboat.users (id, workos_subject, primary_email, status)
VALUES ($1, $2, $3, 'active')`, accountID, "workos_"+accountID, accountID+"@example.test"); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	stableEndpointID := "11111111-1111-4111-8111-111111111111"
	stableEndpoint := "https://" + stableEndpointID + ".tunnels.example.test"
	if _, err := database.SQL().ExecContext(ctx, `
INSERT INTO paperboat.tunnels
  (id, account_id, name, desired_state, access_mode, generation,
   stable_endpoint_id, stable_endpoint, created_by_host_id, created_by_actor_id,
   summary_code, summary_transitioned_at, created_at, updated_at)
VALUES ($1, $2, 'snapshot-bytes', 'active', 'public', 1,
        $3, $4, $5, $2, 'pending', $6, $6, $6)`, tunnelID, accountID,
		stableEndpointID, stableEndpoint, "host_"+suffix, now); err != nil {
		t.Fatal(err)
	}
	payload := []byte(` { "routes" : [], "expires_at" : null, "stable_endpoint" : "` + stableEndpoint + `", "access_mode" : "public", "desired_state" : "active", "name" : "snapshot-bytes", "generation" : 1, "tunnel_id" : "` + tunnelID + `", "kind" : "tunnel_config_snapshot", "schema" : "paperboat.preview-tunnel/v1" } `)
	expected, err := connectorprotocol.NewSnapshot(tunnelID, 1, payload)
	if err != nil {
		t.Fatal(err)
	}
	digest := snapshotDigestBytes(t, expected)
	if _, err := database.SQL().ExecContext(ctx, `
INSERT INTO paperboat.tunnel_config_generations
  (tunnel_id, generation, content_hash, snapshot, activation_state,
   created_by_actor_id, created_at, retained_until)
VALUES ($1, 1, $2, $3, 'pending', $4, $5::timestamptz, $5::timestamptz + interval '90 days')`, tunnelID, digest, payload, accountID, now); err != nil {
		t.Fatal(err)
	}

	var dataType string
	if err := database.SQL().QueryRowContext(ctx, `
SELECT data_type FROM information_schema.columns
WHERE table_schema='paperboat' AND table_name='tunnel_config_generations' AND column_name='snapshot'`).Scan(&dataType); err != nil {
		t.Fatal(err)
	}
	if dataType != "bytea" {
		t.Fatalf("snapshot type before down = %q, want bytea", dataType)
	}

	// Roll back to the version immediately before the snapshot-byte migration.
	// The later preview-carrier migrations are additive and must be included in
	// the rollback, otherwise a single Down would only remove the newest one.
	if err := goose.DownToContext(ctx, database.SQL(), snapshotMigrationsDir, 127); err != nil {
		t.Fatal(err)
	}
	rolledBack = true
	assertSnapshotColumnType(t, ctx, database.SQL(), "jsonb")
	var rollbackHash []byte
	if err := database.SQL().QueryRowContext(ctx, `
SELECT content_hash FROM paperboat.tunnel_config_generations WHERE tunnel_id=$1 AND generation=1`, tunnelID).Scan(&rollbackHash); err != nil {
		t.Fatal(err)
	}
	var rollbackText string
	if err := database.SQL().QueryRowContext(ctx, `
SELECT snapshot::text FROM paperboat.tunnel_config_generations WHERE tunnel_id=$1 AND generation=1`, tunnelID).Scan(&rollbackText); err != nil {
		t.Fatal(err)
	}
	rollbackSnapshot, err := connectorprotocol.NewSnapshot(tunnelID, 1, []byte(rollbackText))
	if err != nil {
		t.Fatalf("rollback snapshot is not accepted by connector protocol: %v", err)
	}
	if !bytes.Equal(rollbackHash, snapshotDigestBytes(t, rollbackSnapshot)) {
		t.Fatalf("rollback content hash does not match connector protocol canonical bytes: snapshot=%q hash=%x", rollbackSnapshot.Payload, rollbackHash)
	}

	edgePayload := []byte(`{ "routes": [], "expires_at": null, "stable_endpoint": "` + stableEndpoint + `", "access_mode": "public", "desired_state": "active", "name": "snapshot unicode café \u2028 \u2029 < > &", "generation": 2, "tunnel_id": "` + tunnelID + `", "kind": "tunnel_config_snapshot", "schema": "paperboat.preview-tunnel/v1" }`)
	edgeExpected, err := connectorprotocol.NewSnapshot(tunnelID, 2, edgePayload)
	if err != nil {
		t.Fatal(err)
	}
	edgeDigest := snapshotDigestBytes(t, edgeExpected)
	if _, err := database.SQL().ExecContext(ctx, `
INSERT INTO paperboat.tunnel_config_generations
  (tunnel_id, generation, previous_generation, content_hash, snapshot, activation_state,
   created_by_actor_id, created_at, retained_until)
VALUES ($1, 2, 1, $2, $3::jsonb, 'pending', $4, $5::timestamptz, $5::timestamptz + interval '90 days')`, tunnelID, edgeDigest, string(edgePayload), accountID, now); err != nil {
		t.Fatal(err)
	}

	if err := goose.UpContext(ctx, database.SQL(), snapshotMigrationsDir); err != nil {
		t.Fatal(err)
	}
	rolledBack = false
	assertSnapshotColumnType(t, ctx, database.SQL(), "bytea")
	var roundTripPayload, roundTripHash []byte
	if err := database.SQL().QueryRowContext(ctx, `
SELECT snapshot, content_hash FROM paperboat.tunnel_config_generations WHERE tunnel_id=$1 AND generation=1`, tunnelID).Scan(&roundTripPayload, &roundTripHash); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(roundTripPayload, expected.Payload) || !bytes.Equal(roundTripHash, digest) || len(roundTripPayload) == 0 {
		t.Fatalf("round-trip content hash mismatch: payload=%q hash=%x", roundTripPayload, roundTripHash)
	}
	var edgeRoundTripPayload, edgeRoundTripHash []byte
	if err := database.SQL().QueryRowContext(ctx, `
SELECT snapshot, content_hash FROM paperboat.tunnel_config_generations WHERE tunnel_id=$1 AND generation=2`, tunnelID).Scan(&edgeRoundTripPayload, &edgeRoundTripHash); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(edgeRoundTripPayload, edgeExpected.Payload) || !bytes.Equal(edgeRoundTripHash, edgeDigest) {
		t.Fatalf("edge-case round-trip does not match connector protocol: payload=%q hash=%x want=%q hash=%x", edgeRoundTripPayload, edgeRoundTripHash, edgeExpected.Payload, edgeDigest)
	}
}

// TestPreviewCarrierEndpointMigrationUpDownUp is guarded separately because
// it changes the shared migration history. Run it only against an isolated
// PostgreSQL database.
func TestPreviewCarrierEndpointMigrationUpDownUp(t *testing.T) {
	dsn := os.Getenv("PAPERBOAT_TEST_DATABASE_DSN")
	if dsn == "" || os.Getenv("PAPERBOAT_TEST_MIGRATION_ROLLBACK") != "1" {
		t.Skip("set PAPERBOAT_TEST_DATABASE_DSN and PAPERBOAT_TEST_MIGRATION_ROLLBACK=1 on an isolated database")
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
	if err := db.Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	configureGooseForSnapshotMigration(t)
	if err := assertCarrierEndpointColumns(ctx, database.SQL(), true); err != nil {
		t.Fatal(err)
	}
	if err := goose.DownToContext(ctx, database.SQL(), snapshotMigrationsDir, 130); err != nil {
		t.Fatal(err)
	}
	rolledBack := true
	t.Cleanup(func() {
		if !rolledBack {
			return
		}
		if err := goose.UpContext(context.Background(), database.SQL(), snapshotMigrationsDir); err != nil {
			t.Errorf("restore carrier endpoint migration after failed test: %v", err)
		}
	})
	if err := assertCarrierEndpointColumns(ctx, database.SQL(), false); err != nil {
		t.Fatal(err)
	}
	if err := goose.UpContext(ctx, database.SQL(), snapshotMigrationsDir); err != nil {
		t.Fatal(err)
	}
	rolledBack = false
	if err := assertCarrierEndpointColumns(ctx, database.SQL(), true); err != nil {
		t.Fatal(err)
	}
}

func snapshotDigestBytes(t *testing.T, snapshot connectorprotocol.Snapshot) []byte {
	t.Helper()
	digest, err := hex.DecodeString(strings.TrimPrefix(snapshot.ContentHash, "sha256:"))
	if err != nil {
		t.Fatalf("decode connector snapshot content hash %q: %v", snapshot.ContentHash, err)
	}
	return digest
}

func configureGooseForSnapshotMigration(t *testing.T) {
	t.Helper()
	goose.SetBaseFS(snapshotMigrationsFS)
	goose.SetTableName("paperboat.goose_db_version")
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatal(err)
	}
}

func assertSnapshotColumnType(t *testing.T, ctx context.Context, database *sql.DB, want string) {
	t.Helper()
	var dataType string
	if err := database.QueryRowContext(ctx, `
SELECT data_type FROM information_schema.columns
WHERE table_schema='paperboat' AND table_name='tunnel_config_generations' AND column_name='snapshot'`).Scan(&dataType); err != nil {
		t.Fatal(err)
	}
	if dataType != want {
		t.Fatalf("snapshot type = %q, want %q", dataType, want)
	}
}

func assertCarrierEndpointColumns(ctx context.Context, database *sql.DB, want bool) error {
	var count int
	if err := database.QueryRowContext(ctx, `
SELECT count(*) FROM information_schema.columns
WHERE table_schema='paperboat' AND table_name='control_tunnel_nodes'
  AND column_name IN ('carrier_endpoint_host','carrier_endpoint_tcp_port','carrier_endpoint_quic_port')`).Scan(&count); err != nil {
		return err
	}
	if (count == 3) != want {
		return fmt.Errorf("carrier endpoint column count = %d, want present=%t", count, want)
	}
	return nil
}
