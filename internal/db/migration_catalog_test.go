package db

import (
	"bytes"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestEmbeddedMigrationVersionsAreUnique(t *testing.T) {
	entries, err := migrationsFS.ReadDir(migrationsDir)
	if err != nil {
		t.Fatal(err)
	}

	versions := make(map[int64]string, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".sql" {
			continue
		}
		prefix, _, ok := strings.Cut(entry.Name(), "_")
		if !ok {
			t.Fatalf("migration %q has no numeric version prefix", entry.Name())
		}
		version, err := strconv.ParseInt(prefix, 10, 64)
		if err != nil {
			t.Fatalf("migration %q has an invalid version prefix: %v", entry.Name(), err)
		}
		if existing, exists := versions[version]; exists {
			t.Fatalf("migration version %d is duplicated by %q and %q", version, existing, entry.Name())
		}
		versions[version] = entry.Name()
	}
}

func TestClientSetupModeMigrationDropsConstraintBeforeRenamingValues(t *testing.T) {
	body, err := migrationsFS.ReadFile("migrations/111_client_setup_mode.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, section := range bytes.Split(body, []byte("-- +goose Down")) {
		drop := bytes.Index(section, []byte("DROP CONSTRAINT user_machines_setup_mode_check"))
		update := bytes.Index(section, []byte("UPDATE user_machines SET setup_mode"))
		if drop < 0 || update < 0 || drop > update {
			t.Fatalf("setup-mode migration must drop the old check constraint before updating constrained values: %s", section)
		}
	}
}
