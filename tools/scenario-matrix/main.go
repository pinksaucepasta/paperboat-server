package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const schemaVersion = 1

type manifest struct {
	SchemaVersion int     `json:"schema_version"`
	Shards        []shard `json:"shards"`
}

type shard struct {
	Name           string   `json:"name"`
	Platform       string   `json:"platform"`
	TimeoutSeconds int      `json:"timeout_seconds"`
	Tests          []string `json:"tests"`
}

type generated struct {
	SchemaVersion int              `json:"schema_version"`
	Include       []generatedShard `json:"include"`
}

type generatedShard struct {
	Name           string `json:"name"`
	Platform       string `json:"platform"`
	TimeoutSeconds int    `json:"timeout_seconds"`
	Run            string `json:"run"`
}

func main() {
	check := flag.Bool("check", false, "fail when the generated matrix is stale")
	flag.Parse()
	if flag.NArg() != 3 {
		fatalf("usage: scenario-matrix [-check] MANIFEST TEST_SOURCE OUTPUT")
	}
	data, err := build(flag.Arg(0), flag.Arg(1))
	if err != nil {
		fatalf("scenario matrix: %v", err)
	}
	output := flag.Arg(2)
	if *check {
		current, err := os.ReadFile(output)
		if err != nil {
			fatalf("read generated matrix: %v", err)
		}
		if !bytes.Equal(current, data) {
			fatalf("%s is stale; run make scenario-matrix-generate", output)
		}
		return
	}
	if err := os.MkdirAll(filepath.Dir(output), 0o755); err != nil {
		fatalf("create output directory: %v", err)
	}
	if err := os.WriteFile(output, data, 0o644); err != nil {
		fatalf("write generated matrix: %v", err)
	}
}

func build(manifestPath, sourcePath string) ([]byte, error) {
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	var input manifest
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		return nil, fmt.Errorf("decode manifest: %w", err)
	}
	if input.SchemaVersion != schemaVersion {
		return nil, fmt.Errorf("schema_version must be %d", schemaVersion)
	}
	declared, err := declaredTests(sourcePath)
	if err != nil {
		return nil, err
	}
	seenShards := make(map[string]struct{}, len(input.Shards))
	assigned := make(map[string]string, len(declared))
	result := generated{SchemaVersion: schemaVersion}
	for _, item := range input.Shards {
		if item.Name == "" || strings.ContainsAny(item.Name, " \\/") {
			return nil, fmt.Errorf("invalid shard name %q", item.Name)
		}
		if _, ok := seenShards[item.Name]; ok {
			return nil, fmt.Errorf("duplicate shard %q", item.Name)
		}
		seenShards[item.Name] = struct{}{}
		if item.Platform != "linux" {
			return nil, fmt.Errorf("shard %q uses unsupported platform %q", item.Name, item.Platform)
		}
		if item.TimeoutSeconds < 30 || item.TimeoutSeconds > 1800 {
			return nil, fmt.Errorf("shard %q timeout must be between 30 and 1800 seconds", item.Name)
		}
		if len(item.Tests) == 0 || len(item.Tests) > 12 {
			return nil, fmt.Errorf("shard %q must contain 1-12 tests", item.Name)
		}
		for _, test := range item.Tests {
			if _, ok := declared[test]; !ok {
				return nil, fmt.Errorf("shard %q names unknown test %q", item.Name, test)
			}
			if previous, ok := assigned[test]; ok {
				return nil, fmt.Errorf("test %q assigned to both %q and %q", test, previous, item.Name)
			}
			assigned[test] = item.Name
		}
		result.Include = append(result.Include, generatedShard{
			Name: item.Name, Platform: item.Platform, TimeoutSeconds: item.TimeoutSeconds,
			Run: "^(" + strings.Join(item.Tests, "|") + ")$",
		})
	}
	var missing []string
	for test := range declared {
		if _, ok := assigned[test]; !ok {
			missing = append(missing, test)
		}
	}
	if len(missing) != 0 {
		sort.Strings(missing)
		return nil, fmt.Errorf("tests missing from bounded shards: %s", strings.Join(missing, ", "))
	}
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func declaredTests(path string) (map[string]struct{}, error) {
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		return nil, fmt.Errorf("parse topology tests: %w", err)
	}
	tests := make(map[string]struct{})
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Recv != nil || !strings.HasPrefix(function.Name.Name, "Test") {
			continue
		}
		tests[function.Name.Name] = struct{}{}
	}
	if len(tests) == 0 {
		return nil, errors.New("topology source declares no tests")
	}
	return tests, nil
}

func fatalf(format string, values ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", values...)
	os.Exit(1)
}
