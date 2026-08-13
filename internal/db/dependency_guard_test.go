package db_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestServerDoesNotDependOnLibPQ(t *testing.T) {
	t.Parallel()
	repoRoot := filepath.Clean(filepath.Join("..", ".."))
	module, err := os.ReadFile(filepath.Join(repoRoot, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(module), "github.com/lib/pq") {
		t.Fatal("go.mod retains forbidden github.com/lib/pq dependency")
	}
	err = filepath.WalkDir(repoRoot, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if entry.Name() == ".git" || entry.Name() == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		file, parseErr := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if parseErr != nil {
			return parseErr
		}
		for _, spec := range file.Decls {
			declaration, ok := spec.(*ast.GenDecl)
			if !ok || declaration.Tok != token.IMPORT {
				continue
			}
			for _, item := range declaration.Specs {
				importSpec := item.(*ast.ImportSpec)
				value, unquoteErr := strconv.Unquote(importSpec.Path.Value)
				if unquoteErr != nil {
					return unquoteErr
				}
				if value == "github.com/lib/pq" {
					t.Fatalf("forbidden lib/pq import remains in %s", path)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
