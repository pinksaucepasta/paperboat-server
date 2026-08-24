package db

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pressly/goose/v3"
)

func TestMigration116UpgradesFrom115AndBackfillsOnlyOwningAccount(t *testing.T) {
	dsn := requiredMigrationTestDSN(t)
	target := newMigration116Database(t, dsn)
	ctx := context.Background()
	if _, err := target.sql.ExecContext(ctx, `CREATE SCHEMA paperboat`); err != nil {
		t.Fatal(err)
	}
	goose.SetBaseFS(migrationsFS)
	goose.SetTableName("paperboat.goose_db_version")
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatal(err)
	}
	if err := goose.UpToContext(ctx, target.sql, migrationsDir, 115); err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	const ownerID = "usr_migration116_owner"
	const foreignID = "usr_migration116_foreign"
	const revokedSessionID = "cls_migration116_shared_endpoint"
	const foreignSessionID = "cls_migration116_foreign"
	const sharedEndpointID = revokedSessionID
	for index, userID := range []string{ownerID, foreignID} {
		rootPublic := bytes.Repeat([]byte{byte(index + 1)}, 32)
		rootFingerprint := sha256.Sum256(rootPublic)
		if _, err := target.sql.ExecContext(ctx, `INSERT INTO paperboat.users (id,workos_subject,primary_email,status) VALUES ($1,$2,$3,'active')`, userID, "workos_"+userID, userID+"@example.test"); err != nil {
			t.Fatal(err)
		}
		if _, err := target.sql.ExecContext(ctx, `INSERT INTO paperboat.account_e2ee_roots (user_id,public_key,fingerprint) VALUES ($1,$2,$3)`, userID, rootPublic, rootFingerprint[:]); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := target.sql.ExecContext(ctx, `INSERT INTO paperboat.cli_client_sessions (id,user_id,client_id,client_label,device_type,os,scopes,state,created_at,approved_at,revoked_at,revocation_reason) VALUES ($1,$2,'client_owner','Owner','desktop','test',ARRAY['projects:connect'],'revoked',$3,$3,$4,'logout'),($5,$6,'client_foreign','Foreign','desktop','test',ARRAY['projects:connect'],'active',$3,$3,NULL,NULL)`, revokedSessionID, ownerID, now.Add(-time.Hour), now, foreignSessionID, foreignID); err != nil {
		t.Fatal(err)
	}

	type endpointRow struct {
		userID      string
		requestID   string
		operationID string
		fingerprint [sha256.Size]byte
		certificate []byte
		noise       [sha256.Size]byte
		quic        [sha256.Size]byte
	}
	rows := []endpointRow{
		{userID: ownerID, requestID: "per_migration116_owner_request", operationID: "operation_migration116_owner", certificate: bytes.Repeat([]byte{11}, 172)},
		{userID: foreignID, requestID: "per_migration116_foreign_request", operationID: "operation_migration116_foreign", certificate: bytes.Repeat([]byte{12}, 172)},
	}
	for index := range rows {
		rows[index].fingerprint = sha256.Sum256(rows[index].certificate)
		rows[index].noise = sha256.Sum256([]byte("noise:" + rows[index].userID))
		rows[index].quic = sha256.Sum256([]byte("quic:" + rows[index].userID))
		requestHash := sha256.Sum256([]byte(rows[index].requestID))
		if _, err := target.sql.ExecContext(ctx, `INSERT INTO paperboat.peer_endpoint_certificates (fingerprint,user_id,endpoint_id,role,generation,serial,certificate,noise_public_key,quic_public_key,issued_at,expires_at,created_at) VALUES ($1,$2,$3,'cli',1,1,$4,$5,$6,$7,$8,$9)`, rows[index].fingerprint[:], rows[index].userID, sharedEndpointID, rows[index].certificate, rows[index].noise[:], rows[index].quic[:], now.Add(-time.Minute), now.Add(time.Hour), now.Add(-2*time.Minute)); err != nil {
			t.Fatal(err)
		}
		if _, err := target.sql.ExecContext(ctx, `INSERT INTO paperboat.peer_endpoint_enrollment_requests (id,operation_key,request_hash,user_id,endpoint_id,generation,role,noise_public_key,quic_public_key,state,certificate_fingerprint,created_at,expires_at,fulfilled_at) VALUES ($1,$2,$3,$4,$5,1,'cli',$6,$7,'fulfilled',$8,$9,$10,$9)`, rows[index].requestID, rows[index].operationID, requestHash[:], rows[index].userID, sharedEndpointID, rows[index].noise[:], rows[index].quic[:], rows[index].fingerprint[:], now.Add(-time.Minute), now.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}

	var ownerState string
	var ownerActive bool
	if err := target.sql.QueryRowContext(ctx, `SELECT request.state,certificate.revoked_at IS NULL FROM paperboat.peer_endpoint_enrollment_requests request JOIN paperboat.peer_endpoint_certificates certificate ON certificate.fingerprint=request.certificate_fingerprint WHERE request.id=$1`, rows[0].requestID).Scan(&ownerState, &ownerActive); err != nil {
		t.Fatal(err)
	}
	if ownerState != "fulfilled" || !ownerActive {
		t.Fatalf("pre-upgrade owner state=%q active=%t", ownerState, ownerActive)
	}

	if err := goose.UpToContext(ctx, target.sql, migrationsDir, 116); err != nil {
		t.Fatal(err)
	}
	if err := goose.UpToContext(ctx, target.sql, migrationsDir, 116); err != nil {
		t.Fatalf("idempotent migration replay: %v", err)
	}

	var ownerCleared bool
	if err := target.sql.QueryRowContext(ctx, `SELECT state='revoked' AND certificate_fingerprint IS NULL AND fulfilled_at IS NULL FROM paperboat.peer_endpoint_enrollment_requests WHERE id=$1`, rows[0].requestID).Scan(&ownerCleared); err != nil {
		t.Fatal(err)
	}
	var ownerReason string
	var ownerRevokedAt time.Time
	if err := target.sql.QueryRowContext(ctx, `SELECT revocation_reason,revoked_at FROM paperboat.peer_endpoint_certificates WHERE fingerprint=$1`, rows[0].fingerprint[:]).Scan(&ownerReason, &ownerRevokedAt); err != nil {
		t.Fatal(err)
	}
	var ownerLedgerCount int
	var ownerLedgerReason string
	if err := target.sql.QueryRowContext(ctx, `SELECT count(*),min(reason) FROM paperboat.peer_endpoint_certificate_revocations WHERE user_id=$1 AND certificate_fingerprint=$2`, ownerID, rows[0].fingerprint[:]).Scan(&ownerLedgerCount, &ownerLedgerReason); err != nil {
		t.Fatal(err)
	}
	if !ownerCleared || ownerReason != "client_revoked" || !ownerRevokedAt.Equal(now) || ownerLedgerCount != 1 || ownerLedgerReason != "client_revoked" {
		t.Fatalf("owner cleared=%t reason=%q revoked_at=%s ledger_count=%d ledger_reason=%q", ownerCleared, ownerReason, ownerRevokedAt, ownerLedgerCount, ownerLedgerReason)
	}

	var foreignState string
	var foreignFingerprintPresent, foreignActive bool
	if err := target.sql.QueryRowContext(ctx, `SELECT state,certificate_fingerprint IS NOT NULL FROM paperboat.peer_endpoint_enrollment_requests WHERE id=$1`, rows[1].requestID).Scan(&foreignState, &foreignFingerprintPresent); err != nil {
		t.Fatal(err)
	}
	if err := target.sql.QueryRowContext(ctx, `SELECT revoked_at IS NULL FROM paperboat.peer_endpoint_certificates WHERE fingerprint=$1`, rows[1].fingerprint[:]).Scan(&foreignActive); err != nil {
		t.Fatal(err)
	}
	var foreignLedgerCount int
	if err := target.sql.QueryRowContext(ctx, `SELECT count(*) FROM paperboat.peer_endpoint_certificate_revocations WHERE user_id=$1 AND certificate_fingerprint=$2`, foreignID, rows[1].fingerprint[:]).Scan(&foreignLedgerCount); err != nil {
		t.Fatal(err)
	}
	if foreignState != "fulfilled" || !foreignFingerprintPresent || !foreignActive || foreignLedgerCount != 0 {
		t.Fatalf("foreign state=%q fingerprint_present=%t active=%t ledger_count=%d", foreignState, foreignFingerprintPresent, foreignActive, foreignLedgerCount)
	}
}

func TestMigration116RepairsMarked115WithoutLifecycleDDL(t *testing.T) {
	dsn := requiredMigrationTestDSN(t)
	target := newMigration116Database(t, dsn)
	ctx := context.Background()
	if _, err := target.sql.ExecContext(ctx, `CREATE SCHEMA paperboat`); err != nil {
		t.Fatal(err)
	}
	goose.SetBaseFS(migrationsFS)
	goose.SetTableName("paperboat.goose_db_version")
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatal(err)
	}
	if err := goose.UpToContext(ctx, target.sql, migrationsDir, 114); err != nil {
		t.Fatal(err)
	}
	// Reproduce the deployed history collision: Goose records version 115, but
	// the database still has the pre-lifecycle schema from version 114.
	if _, err := target.sql.ExecContext(ctx, `INSERT INTO paperboat.goose_db_version (version_id,is_applied) VALUES (115,true)`); err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 8, 25, 13, 0, 0, 0, time.UTC)
	const ownerID = "usr_migration116_collision_owner"
	const foreignID = "usr_migration116_collision_foreign"
	const staleSessionID = "cls_migration116_collision_shared"
	for index, userID := range []string{ownerID, foreignID} {
		rootPublic := bytes.Repeat([]byte{byte(index + 21)}, 32)
		rootFingerprint := sha256.Sum256(rootPublic)
		if _, err := target.sql.ExecContext(ctx, `INSERT INTO paperboat.users (id,workos_subject,primary_email,status) VALUES ($1,$2,$3,'active')`, userID, "workos_"+userID, userID+"@example.test"); err != nil {
			t.Fatal(err)
		}
		if _, err := target.sql.ExecContext(ctx, `INSERT INTO paperboat.account_e2ee_roots (user_id,public_key,fingerprint) VALUES ($1,$2,$3)`, userID, rootPublic, rootFingerprint[:]); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := target.sql.ExecContext(ctx, `INSERT INTO paperboat.cli_client_sessions (id,user_id,client_id,client_label,device_type,os,scopes,state,created_at,approved_at,revoked_at,revocation_reason) VALUES ($1,$2,'client_collision_owner','Owner','desktop','test',ARRAY['projects:connect'],'revoked',$3,$3,$4,'logout')`, staleSessionID, ownerID, now.Add(-time.Hour), now); err != nil {
		t.Fatal(err)
	}

	type collisionEndpoint struct {
		userID      string
		requestID   string
		operationID string
		fingerprint [sha256.Size]byte
		certificate []byte
		noise       [sha256.Size]byte
		quic        [sha256.Size]byte
	}
	endpoints := []collisionEndpoint{
		{userID: ownerID, requestID: "per_migration116_collision_owner", operationID: "operation_migration116_collision_owner", certificate: bytes.Repeat([]byte{31}, 172)},
		{userID: foreignID, requestID: "per_migration116_collision_foreign", operationID: "operation_migration116_collision_foreign", certificate: bytes.Repeat([]byte{32}, 172)},
	}
	for index := range endpoints {
		endpoints[index].fingerprint = sha256.Sum256(endpoints[index].certificate)
		endpoints[index].noise = sha256.Sum256([]byte("noise:" + endpoints[index].userID))
		endpoints[index].quic = sha256.Sum256([]byte("quic:" + endpoints[index].userID))
		requestHash := sha256.Sum256([]byte(endpoints[index].requestID))
		if _, err := target.sql.ExecContext(ctx, `INSERT INTO paperboat.peer_endpoint_certificates (fingerprint,user_id,endpoint_id,role,generation,serial,certificate,noise_public_key,quic_public_key,issued_at,expires_at,created_at) VALUES ($1,$2,$3,'cli',1,1,$4,$5,$6,$7,$8,$9)`, endpoints[index].fingerprint[:], endpoints[index].userID, staleSessionID, endpoints[index].certificate, endpoints[index].noise[:], endpoints[index].quic[:], now.Add(-time.Minute), now.Add(time.Hour), now.Add(-2*time.Minute)); err != nil {
			t.Fatal(err)
		}
		if _, err := target.sql.ExecContext(ctx, `INSERT INTO paperboat.peer_endpoint_enrollment_requests (id,operation_key,request_hash,user_id,endpoint_id,generation,role,noise_public_key,quic_public_key,state,certificate_fingerprint,created_at,expires_at,fulfilled_at) VALUES ($1,$2,$3,$4,$5,1,'cli',$6,$7,'fulfilled',$8,$9,$10,$9)`, endpoints[index].requestID, endpoints[index].operationID, requestHash[:], endpoints[index].userID, staleSessionID, endpoints[index].noise[:], endpoints[index].quic[:], endpoints[index].fingerprint[:], now.Add(-time.Minute), now.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}

	if err := goose.UpToContext(ctx, target.sql, migrationsDir, 116); err != nil {
		t.Fatal(err)
	}
	if err := goose.UpToContext(ctx, target.sql, migrationsDir, 116); err != nil {
		t.Fatalf("idempotent migration replay: %v", err)
	}

	for _, constraint := range []struct{ table, name string }{
		{"peer_endpoint_enrollment_requests", "peer_endpoint_enrollment_requests_state_check"},
		{"peer_endpoint_certificates", "peer_endpoint_certificates_revocation_reason_check"},
		{"peer_endpoint_certificate_revocations", "peer_endpoint_certificate_revocations_reason_check"},
	} {
		var validated bool
		if err := target.sql.QueryRowContext(ctx, `SELECT constraint_row.convalidated FROM pg_constraint constraint_row JOIN pg_class table_row ON table_row.oid=constraint_row.conrelid JOIN pg_namespace schema_row ON schema_row.oid=table_row.relnamespace WHERE schema_row.nspname='paperboat' AND table_row.relname=$1 AND constraint_row.conname=$2`, constraint.table, constraint.name).Scan(&validated); err != nil {
			t.Fatal(err)
		}
		if !validated {
			t.Fatalf("constraint %s is not validated", constraint.name)
		}
	}
	var denialTableExists bool
	if err := target.sql.QueryRowContext(ctx, `SELECT to_regclass('paperboat.peer_endpoint_enrollment_denials') IS NOT NULL`).Scan(&denialTableExists); err != nil {
		t.Fatal(err)
	}
	if !denialTableExists {
		t.Fatal("migration 116 did not create peer_endpoint_enrollment_denials")
	}

	assertCollisionEndpoint := func(endpoint collisionEndpoint, wantRevoked bool) {
		t.Helper()
		var requestState string
		var requestCleared bool
		if err := target.sql.QueryRowContext(ctx, `SELECT state,certificate_fingerprint IS NULL AND fulfilled_at IS NULL FROM paperboat.peer_endpoint_enrollment_requests WHERE id=$1`, endpoint.requestID).Scan(&requestState, &requestCleared); err != nil {
			t.Fatal(err)
		}
		var certificateRevoked bool
		var reason string
		if err := target.sql.QueryRowContext(ctx, `SELECT revoked_at IS NOT NULL,coalesce(revocation_reason,'') FROM paperboat.peer_endpoint_certificates WHERE fingerprint=$1`, endpoint.fingerprint[:]).Scan(&certificateRevoked, &reason); err != nil {
			t.Fatal(err)
		}
		var ledgerCount int
		if err := target.sql.QueryRowContext(ctx, `SELECT count(*) FROM paperboat.peer_endpoint_certificate_revocations WHERE user_id=$1 AND certificate_fingerprint=$2`, endpoint.userID, endpoint.fingerprint[:]).Scan(&ledgerCount); err != nil {
			t.Fatal(err)
		}
		if wantRevoked {
			if requestState != "revoked" || !requestCleared || !certificateRevoked || reason != "client_revoked" || ledgerCount != 1 {
				t.Fatalf("revoked endpoint state=%q cleared=%t certificate_revoked=%t reason=%q ledger_count=%d", requestState, requestCleared, certificateRevoked, reason, ledgerCount)
			}
			return
		}
		if requestState != "fulfilled" || requestCleared || certificateRevoked || reason != "" || ledgerCount != 0 {
			t.Fatalf("isolated endpoint state=%q cleared=%t certificate_revoked=%t reason=%q ledger_count=%d", requestState, requestCleared, certificateRevoked, reason, ledgerCount)
		}
	}
	assertCollisionEndpoint(endpoints[0], true)
	assertCollisionEndpoint(endpoints[1], false)

	const triggerSessionID = "cls_migration116_collision_trigger"
	triggerCertificate := bytes.Repeat([]byte{33}, 172)
	triggerFingerprint := sha256.Sum256(triggerCertificate)
	triggerNoise := sha256.Sum256([]byte("noise:" + triggerSessionID))
	triggerQUIC := sha256.Sum256([]byte("quic:" + triggerSessionID))
	triggerRequestHash := sha256.Sum256([]byte("per_migration116_collision_trigger"))
	if _, err := target.sql.ExecContext(ctx, `INSERT INTO paperboat.cli_client_sessions (id,user_id,client_id,client_label,device_type,os,scopes,state,created_at,approved_at) VALUES ($1,$2,'client_collision_trigger','Trigger','desktop','test',ARRAY['projects:connect'],'active',$3,$3)`, triggerSessionID, ownerID, now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := target.sql.ExecContext(ctx, `INSERT INTO paperboat.peer_endpoint_certificates (fingerprint,user_id,endpoint_id,role,generation,serial,certificate,noise_public_key,quic_public_key,issued_at,expires_at,created_at) VALUES ($1,$2,$3,'cli',1,2,$4,$5,$6,$7,$8,$9)`, triggerFingerprint[:], ownerID, triggerSessionID, triggerCertificate, triggerNoise[:], triggerQUIC[:], now.Add(-time.Minute), now.Add(time.Hour), now.Add(-2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := target.sql.ExecContext(ctx, `INSERT INTO paperboat.peer_endpoint_enrollment_requests (id,operation_key,request_hash,user_id,endpoint_id,generation,role,noise_public_key,quic_public_key,state,certificate_fingerprint,created_at,expires_at,fulfilled_at) VALUES ('per_migration116_collision_trigger','operation_migration116_collision_trigger',$1,$2,$3,1,'cli',$4,$5,'fulfilled',$6,$7,$8,$7)`, triggerRequestHash[:], ownerID, triggerSessionID, triggerNoise[:], triggerQUIC[:], triggerFingerprint[:], now.Add(-time.Minute), now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := target.sql.ExecContext(ctx, `UPDATE paperboat.cli_client_sessions SET state='revoked',revoked_at=$2,revocation_reason='logout' WHERE id=$1`, triggerSessionID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := target.sql.ExecContext(ctx, `UPDATE paperboat.cli_client_sessions SET revoked_at=$2,revocation_reason='logout' WHERE id=$1`, triggerSessionID, now); err != nil {
		t.Fatal(err)
	}
	triggerEndpoint := collisionEndpoint{userID: ownerID, requestID: "per_migration116_collision_trigger", fingerprint: triggerFingerprint}
	assertCollisionEndpoint(triggerEndpoint, true)

	deniedRequestHash := sha256.Sum256([]byte("per_migration116_collision_denied"))
	if _, err := target.sql.ExecContext(ctx, `INSERT INTO paperboat.peer_endpoint_enrollment_requests (id,operation_key,request_hash,user_id,endpoint_id,generation,role,noise_public_key,quic_public_key,state,created_at,expires_at) VALUES ('per_migration116_collision_denied','operation_migration116_collision_denied',$1,$2,'cls_migration116_collision_denied',1,'cli',$3,$4,'denied',$5,$6)`, deniedRequestHash[:], ownerID, bytes.Repeat([]byte{41}, 32), bytes.Repeat([]byte{42}, 32), now, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := target.sql.ExecContext(ctx, `INSERT INTO paperboat.peer_endpoint_enrollment_denials (operation_id,request_id,user_id,created_at) VALUES ('operation.migration116.collision.denial','per_migration116_collision_denied',$1,$2)`, ownerID, now); err != nil {
		t.Fatal(err)
	}
}

func requiredMigrationTestDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("PAPERBOAT_TEST_DATABASE_DSN")
	if dsn != "" {
		return dsn
	}
	if os.Getenv("CI") != "" {
		t.Fatal("PAPERBOAT_TEST_DATABASE_DSN is required in CI")
	}
	t.Skip("set PAPERBOAT_TEST_DATABASE_DSN to run the migration 116 upgrade test")
	return ""
}

func newMigration116Database(t *testing.T, dsn string) *DB {
	t.Helper()
	base, err := url.Parse(dsn)
	if err != nil {
		t.Fatal("refusing to parse PAPERBOAT_TEST_DATABASE_DSN")
	}
	production, productionErr := url.Parse(os.Getenv("PAPERBOAT_DATABASE_DSN"))
	databaseName := strings.ToLower(strings.Trim(base.Path, "/"))
	productionMatch := os.Getenv("PAPERBOAT_DATABASE_DSN") != "" && productionErr == nil && strings.EqualFold(base.Host, production.Host) && strings.EqualFold(strings.Trim(base.Path, "/"), strings.Trim(production.Path, "/"))
	if !strings.HasSuffix(databaseName, "_test") || productionMatch {
		t.Fatal("refusing to create a migration database from an unsafe PAPERBOAT_TEST_DATABASE_DSN")
	}
	adminURL := *base
	adminURL.Path, adminURL.RawPath = "/postgres", ""
	admin, err := Open(config.Database{Driver: "postgres", DSN: adminURL.String()})
	if err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("paperboat_migration116_%d_test", time.Now().UnixNano())
	identifier := pgx.Identifier{name}.Sanitize()
	if _, err := admin.sql.ExecContext(context.Background(), "CREATE DATABASE "+identifier); err != nil {
		_ = admin.Close()
		t.Fatal(err)
	}
	targetURL := *base
	targetURL.Path, targetURL.RawPath = "/"+name, ""
	target, err := Open(config.Database{Driver: "postgres", DSN: targetURL.String()})
	if err != nil {
		_, _ = admin.sql.ExecContext(context.Background(), "DROP DATABASE "+identifier+" WITH (FORCE)")
		_ = admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = target.Close()
		if _, err := admin.sql.ExecContext(context.Background(), "DROP DATABASE "+identifier+" WITH (FORCE)"); err != nil {
			t.Errorf("drop migration test database: %v", err)
		}
		_ = admin.Close()
	})
	return target
}
