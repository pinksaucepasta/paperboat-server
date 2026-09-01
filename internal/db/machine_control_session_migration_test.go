package db

import (
	"os"
	"strings"
	"testing"
)

func TestMachineControlCurrentSessionMigrationIsGenerationFenced(t *testing.T) {
	raw, err := os.ReadFile("migrations/137_machine_control_current_sessions.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(raw)
	for _, required := range []string{
		"CREATE TABLE machine_control_sessions",
		"machine_id text PRIMARY KEY",
		"session_generation bigint NOT NULL",
		"credential_jti text NOT NULL UNIQUE",
		"machine_control_renewals_machine_session_generation_idx",
		"FOREIGN KEY (operation_id, machine_id, installation_generation)",
	} {
		if !strings.Contains(sql, required) {
			t.Fatalf("migration 137 missing %q", required)
		}
	}
}
