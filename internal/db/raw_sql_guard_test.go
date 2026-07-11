package db_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func TestProductionCodeDoesNotUseRawSQLContextMethods(t *testing.T) {
	repoRoot := filepath.Clean(filepath.Join("..", ".."))
	disallowed := regexp.MustCompile(`\.(ExecContext|QueryContext|QueryRowContext|PrepareContext)\s*\(`)
	allowlist := map[string]struct{}{
		filepath.Join("internal", "db", "db.go"):         {},
		filepath.Join("internal", "db", "migrations.go"): {},
	}

	var violations []string
	err := filepath.WalkDir(repoRoot, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			rel, err := filepath.Rel(repoRoot, path)
			if err != nil {
				return err
			}
			switch rel {
			case ".git", filepath.Join("internal", "db", "dbsqlc"):
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, err := filepath.Rel(repoRoot, path)
		if err != nil {
			return err
		}
		if _, ok := allowlist[rel]; ok {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, match := range disallowed.FindAllStringIndex(string(data), -1) {
			line := 1 + strings.Count(string(data[:match[0]]), "\n")
			violations = append(violations, rel+":"+strconv.Itoa(line))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(violations) > 0 {
		t.Fatalf("raw database/sql context methods found outside sqlc/database allowlist:\n%s", strings.Join(violations, "\n"))
	}
}
