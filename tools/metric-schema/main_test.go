package main

import (
	"encoding/json"
	"testing"
)

func TestCanonicalDocumentIsUniqueAndSorted(t *testing.T) {
	data, err := canonicalDocument()
	if err != nil {
		t.Fatal(err)
	}
	var value document
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatal(err)
	}
	if value.SchemaVersion != schemaVersion || len(value.Metrics) == 0 {
		t.Fatalf("document=%+v", value)
	}
	for index, item := range value.Metrics {
		if item.Kind != "counter" && item.Kind != "gauge" {
			t.Fatalf("metric %q kind=%q", item.Name, item.Kind)
		}
		if index > 0 && value.Metrics[index-1].Name >= item.Name {
			t.Fatalf("metrics are not uniquely sorted at %q", item.Name)
		}
	}
}

func TestRealMetricsRouteMatchesProcessSchema(t *testing.T) {
	if err := verifyHandler(); err != nil {
		t.Fatal(err)
	}
}
