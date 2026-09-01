package controlplane

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
)

func TestTunnelEdgeRouteAssignmentIDIsDeterministicAndTupleBound(t *testing.T) {
	candidate := dbsqlc.ListReadyTunnelEdgeRouteCandidatesV1Row{
		AccountID: "acct_01", TunnelID: "tun_01", RouteID: "route_01",
		ConnectorID: "connector_01", ConnectorSessionID: sql.NullString{String: "session_01", Valid: true},
		ConnectorGeneration: 2, ConnectorProcessGeneration: 3, ConfigGeneration: 4,
		ConfigContentHash: bytes.Repeat([]byte{0x42}, 32), EdgeNodeID: "edge_01", EdgeProcessEpoch: "epoch_0001",
	}
	first := tunnelEdgeRouteAssignmentID(candidate, 5)
	if first == "" || first != tunnelEdgeRouteAssignmentID(candidate, 5) || !validTunnelEdgeIdentifier(first) {
		t.Fatalf("assignment ID is not stable and valid: %q", first)
	}
	for name, mutate := range map[string]func(*dbsqlc.ListReadyTunnelEdgeRouteCandidatesV1Row){
		"generation": func(row *dbsqlc.ListReadyTunnelEdgeRouteCandidatesV1Row) { row.ConfigGeneration++ },
		"connector session": func(row *dbsqlc.ListReadyTunnelEdgeRouteCandidatesV1Row) {
			row.ConnectorSessionID.String = "session_02"
		},
		"edge process":          func(row *dbsqlc.ListReadyTunnelEdgeRouteCandidatesV1Row) { row.EdgeProcessEpoch = "epoch_0002" },
		"assignment generation": func(row *dbsqlc.ListReadyTunnelEdgeRouteCandidatesV1Row) { row.ConfigContentHash[0] ^= 1 },
	} {
		t.Run(name, func(t *testing.T) {
			changed := candidate
			mutate(&changed)
			if got := tunnelEdgeRouteAssignmentID(changed, 5); got == first {
				t.Fatalf("tuple mutation kept assignment ID %q", got)
			}
		})
	}
}

func TestCanonicalRouteObservationRequiresOneExplicitState(t *testing.T) {
	for _, test := range []struct {
		name     string
		state    string
		observed string
		want     string
		wantErr  bool
	}{
		{name: "state", state: "ready", want: "ready"},
		{name: "observed state", observed: "draining", want: "draining"},
		{name: "matching aliases", state: "failed", observed: "failed", want: "failed"},
		{name: "missing", wantErr: true},
		{name: "unknown", state: "started", wantErr: true},
		{name: "conflicting aliases", state: "ready", observed: "degraded", wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := (RouteObservation{State: test.state, ObservedState: test.observed}).canonicalObservedState()
			if test.wantErr {
				if !errors.Is(err, ErrInvalidUsageReport) {
					t.Fatalf("error = %v, want ErrInvalidUsageReport", err)
				}
				return
			}
			if err != nil || got != test.want {
				t.Fatalf("state = %q, error = %v, want %q", got, err, test.want)
			}
		})
	}
}

func TestTunnelEdgeRouteAssignmentRequestValidation(t *testing.T) {
	valid := TunnelEdgeRouteAssignmentRequest{
		AssignmentID: "asn_route_01", AssignmentGeneration: 2, AccountID: "acct_01", TunnelID: "tun_01",
		ConnectorID: "con_01", ConnectorGeneration: 3, ConnectorSessionID: "ses_01", ConnectorProcessGeneration: 4,
		ConfigGeneration: 5, ConfigContentHash: make([]byte, 32), EdgeNodeID: "edge_01", EdgeProcessEpoch: "epoch_0001", RouteID: "rte_01",
	}
	if err := validateTunnelEdgeRouteAssignmentRequest(valid); err != nil {
		t.Fatalf("valid request error = %v", err)
	}
	for name, mutate := range map[string]func(*TunnelEdgeRouteAssignmentRequest){
		"spaced assignment": func(r *TunnelEdgeRouteAssignmentRequest) { r.AssignmentID = " asn_route_01" },
		"unsafe node":       func(r *TunnelEdgeRouteAssignmentRequest) { r.EdgeNodeID = "edge/node" },
		"short epoch":       func(r *TunnelEdgeRouteAssignmentRequest) { r.EdgeProcessEpoch = "epoch" },
		"short hash":        func(r *TunnelEdgeRouteAssignmentRequest) { r.ConfigContentHash = make([]byte, 31) },
		"zero generation":   func(r *TunnelEdgeRouteAssignmentRequest) { r.AssignmentGeneration = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if !errors.Is(validateTunnelEdgeRouteAssignmentRequest(candidate), ErrAssignmentInvalid) {
				t.Fatal("invalid request was accepted")
			}
		})
	}
}

func TestTunnelEdgeRouteJSONIsOpaqueAndCarriesExactFence(t *testing.T) {
	row := dbsqlc.ListTunnelEdgeRouteAssignmentsForNodeV1Row{
		AssignmentID: "asn_route_01", AssignmentGeneration: 2, RouteID: "rte_01", RouteRevision: 3,
		AccountID: "acct_01", TunnelID: "tun_01", ConnectorID: "con_01", ConnectorGeneration: 4,
		ConnectorSessionID: "ses_01", ConnectorProcessGeneration: 5, ConfigGeneration: 6,
		ConfigContentHash: make([]byte, 32), EdgeNodeID: "edge_01", EdgeProcessEpoch: "epoch_0001",
		EdgeFailureDomain: "fsn1", Kind: "tunnel_http_wss", PublicHost: "app.example.test",
		MatchType: "exact", MatchHostname: sql.NullString{String: "app.example.test", Valid: true},
		Priority: 100, Protocol: "http", OriginScheme: "http", PreserveHost: true, State: "active", ObservedState: "ready",
		DomainBindings: `[{"id":"dom_1","hostname":"*.customer.example","match_type":"one_label_wildcard","generation":2}]`,
	}
	value := tunnelEdgeRouteJSON(row)
	if value["assignment_id"] != row.AssignmentID || value["assignment_generation"] != row.AssignmentGeneration || value["edge_process_epoch"] != row.EdgeProcessEpoch {
		t.Fatalf("binding = %#v", value)
	}
	if value["config_content_hash"] != "sha256:"+"0000000000000000000000000000000000000000000000000000000000000000" {
		t.Fatalf("config hash = %#v", value["config_content_hash"])
	}
	if _, present := value["origin_address"]; present {
		t.Fatal("opaque edge projection exposed origin_address")
	}
	if got, ok := value["domain_bindings"].(json.RawMessage); !ok || !bytes.Equal(got, []byte(row.DomainBindings)) {
		t.Fatalf("domain bindings = %#v", value["domain_bindings"])
	}
	target, ok := value["target"].(map[string]any)
	if !ok || target["route_id"] != row.RouteID || !reflect.DeepEqual(target["connector_session_id"], row.ConnectorSessionID) {
		t.Fatalf("opaque target = %#v", value["target"])
	}
}
