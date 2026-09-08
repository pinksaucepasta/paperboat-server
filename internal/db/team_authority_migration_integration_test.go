package db

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/config"
)

// A transaction-local schema exercises real migration SQL without rolling back
// the shared test schema or disturbing concurrently running feature fixtures.
func TestTeamAuthorityMigrationPreservesAccess(t *testing.T) {
	dsn := os.Getenv("PAPERBOAT_TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL DSN required")
	}
	if err := ValidateIsolatedTestDSN(dsn, os.Getenv("PAPERBOAT_DATABASE_DSN")); err != nil {
		t.Fatal(err)
	}
	store, err := Open(config.Database{Driver: "postgres", DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tx, err := store.SQL().BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	schema := "team_migration_" + strings.ReplaceAll(time.Now().Format("150405.000000000"), ".", "")
	for _, q := range []string{`CREATE SCHEMA ` + schema, `SET LOCAL search_path TO ` + schema, `CREATE TABLE users(id text PRIMARY KEY); CREATE TABLE user_machines(id text PRIMARY KEY); INSERT INTO users VALUES('owner'),('member'),('inactive'),('ungranted')`} {
		if _, err = tx.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	apply := func(name, direction string) {
		t.Helper()
		raw, e := migrationsFS.ReadFile("migrations/" + name)
		if e != nil {
			t.Fatal(e)
		}
		parts := strings.Split(string(raw), "-- +goose Down")
		sql := strings.TrimPrefix(parts[0], "-- +goose Up")
		if direction == "down" {
			sql = parts[1]
		}
		if _, e = tx.ExecContext(ctx, sql); e != nil {
			t.Fatalf("%s %s: %v", name, direction, e)
		}
	}
	apply("160_environment_vault_scopes.sql", "up")
	apply("162_environment_personal_rotation.sql", "up")
	fixtures := []string{`INSERT INTO environment_vault_teams(team_id,owner_account,generation,key_epoch) VALUES('team','owner',9,3)`, `INSERT INTO environment_vault_team_members(team_id,account_id,membership_generation,role,active,grant_epoch) VALUES('team','owner',2,'owner',true,3),('team','member',7,'member',true,3),('team','inactive',4,'member',false,3),('team','ungranted',6,'member',true,0)`, `INSERT INTO environment_vault_team_grants(team_id,account_id,membership_generation,team_epoch,recipient_vault_generation,recipient_sharing_public,document_id,envelope,sender_writer_public,acknowledged) VALUES('team','member',7,3,11,decode(repeat('01',32),'hex'),'sha256:'||repeat('1',64),decode('012345','hex'),decode(repeat('02',32),'hex'),true)`}
	for _, q := range fixtures {
		if _, err = tx.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	apply("165_team_authority.sql", "up")
	var owner string
	var generation int
	if err = tx.QueryRowContext(ctx, `SELECT owner_account,generation FROM teams WHERE team_id='team'`).Scan(&owner, &generation); err != nil || owner != "owner" || generation != 9 {
		t.Fatal("team identity changed", owner, generation, err)
	}
	var rows int
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM team_members WHERE role='member'`).Scan(&rows); err != nil || rows != 4 {
		t.Fatal("migration elevated a role", rows, err)
	}
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM team_resource_grants WHERE active AND permission='write' AND account_id IN('owner','member')`).Scan(&rows); err != nil || rows != 2 {
		t.Fatal("existing grants lost", rows, err)
	}
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM team_resource_grants WHERE account_id IN('inactive','ungranted') OR resource_kind<>'env'`).Scan(&rows); err != nil || rows != 0 {
		t.Fatal("migration expanded access", rows, err)
	}
	var epoch, memberGeneration int
	var envelope string
	if err = tx.QueryRowContext(ctx, `SELECT m.membership_generation,v.grant_epoch,encode(g.envelope,'hex') FROM team_members m JOIN environment_vault_team_members v USING(team_id,account_id) JOIN environment_vault_team_grants g USING(team_id,account_id) WHERE m.account_id='member'`).Scan(&memberGeneration, &epoch, &envelope); err != nil || memberGeneration != 7 || epoch != 3 || envelope != "012345" {
		t.Fatal("cryptographic binding changed", memberGeneration, epoch, envelope, err)
	}
	apply("165_team_authority.sql", "down")
	apply("165_team_authority.sql", "up")
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM team_resource_grants WHERE active`).Scan(&rows); err != nil || rows != 2 {
		t.Fatal("migration round trip changed grants", rows, err)
	}
}
