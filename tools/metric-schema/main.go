package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"

	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/controlplane"
	"github.com/pinksaucepasta/paperboat-server/internal/httpapi"
	"github.com/pinksaucepasta/paperboat-server/internal/observability"
)

const schemaVersion = 1

type document struct {
	SchemaVersion int      `json:"schema_version"`
	Metrics       []metric `json:"metrics"`
}

type metric struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
}

func main() {
	write := flag.Bool("write", false, "write the canonical metric schema")
	flag.Parse()
	if flag.NArg() != 1 {
		fatalf("usage: metric-schema [-write] DOCUMENT")
	}
	data, err := canonicalDocument()
	if err != nil {
		fatalf("metric schema: %v", err)
	}
	path := flag.Arg(0)
	if *write {
		if err := os.WriteFile(path, data, 0o644); err != nil {
			fatalf("write metric schema: %v", err)
		}
		return
	}
	current, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(current, data) {
		fatalf("%s is stale; run make metrics-generate", path)
	}
	if err := verifyHandler(); err != nil {
		fatalf("metric handler: %v", err)
	}
}

func canonicalDocument() ([]byte, error) {
	names := append(observability.MetricNames(), controlplane.DiagnosticMetricNames()...)
	sort.Strings(names)
	metrics := make([]metric, 0, len(names))
	for index, name := range names {
		if index > 0 && names[index-1] == name {
			return nil, fmt.Errorf("duplicate metric %q", name)
		}
		kind := "gauge"
		if len(name) >= len("_total") && name[len(name)-len("_total"):] == "_total" {
			kind = "counter"
		}
		metrics = append(metrics, metric{Name: name, Kind: kind})
	}
	data, err := json.MarshalIndent(document{SchemaVersion: schemaVersion, Metrics: metrics}, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func verifyHandler() error {
	router := httpapi.NewRouter(httpapi.Options{Config: config.Default(), Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	request.RemoteAddr = "127.0.0.1:1234"
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		return fmt.Errorf("status %d", recorder.Code)
	}
	var response struct {
		Data map[string]int64 `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		return err
	}
	want := observability.MetricNames()
	got := make([]string, 0, len(response.Data))
	for name := range response.Data {
		got = append(got, name)
	}
	sort.Strings(got)
	if fmt.Sprint(got) != fmt.Sprint(want) {
		return fmt.Errorf("process metrics differ: got %v want %v", got, want)
	}
	return nil
}

func fatalf(format string, values ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", values...)
	os.Exit(1)
}
