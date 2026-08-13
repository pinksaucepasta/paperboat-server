package db_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGeneratedQueriesUsePGXV5Driver(t *testing.T) {
	t.Parallel()
	path := filepath.Join("dbsqlc", "db.go")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, required := range []string{
		`"github.com/jackc/pgx/v5"`,
		`"github.com/jackc/pgx/v5/pgconn"`,
		`Exec(context.Context, string, ...interface{}) (pgconn.CommandTag, error)`,
		`WithTx(tx pgx.Tx)`,
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("generated pgx v5 boundary is missing %q", required)
		}
	}
	for _, forbidden := range []string{`"database/sql"`, `"github.com/lib/pq"`, `*sql.Tx`} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("generated query driver contains forbidden boundary %q", forbidden)
		}
	}
}
