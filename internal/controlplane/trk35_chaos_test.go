package controlplane

import (
	"bytes"
	"database/sql"
	"errors"
	"testing"

	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
)

// TestTRK35EdgeProcessReplacementPublishesNewFenceWithoutErasingLKG models the
// bounded handoff used by an edge process. The old assignment remains the
// last-known-good projection while the replacement is staged. A late detach
// for the old immutable assignment may remove only that assignment, never the
// replacement that carries a new process/session fence.
func TestTRK35EdgeProcessReplacementPublishesNewFenceWithoutErasingLKG(t *testing.T) {
	configHash := bytes.Repeat([]byte{0x35}, 32)
	old := dbsqlc.ListReadyTunnelEdgeRouteCandidatesV1Row{
		AccountID: "acct_trk35", TunnelID: "tun_trk35", RouteID: "route_trk35", RouteGeneration: 7,
		ConnectorID: "connector_trk35", HostID: "host_trk35",
		MachineIdentityPublicKey: sql.NullString{String: "machine-key", Valid: true},
		ConnectorGeneration:      4, ConnectorSessionID: sql.NullString{String: "session_old", Valid: true},
		ConnectorProcessGeneration: 9, ConfigGeneration: 12, ConfigContentHash: configHash,
		EdgeNodeID: "edge_trk35", EdgeProcessEpoch: "epoch_old_0001",
	}
	oldID := tunnelEdgeRouteAssignmentID(old, 1)
	oldRow := trk35RouteAssignmentRow(old, oldID, 1, "active", "ready")

	// Replacement changes both process fences. Assignment generation also
	// advances, so a replacement can never alias the LKG assignment.
	replacement := old
	replacement.ConnectorSessionID = sql.NullString{String: "session_new", Valid: true}
	replacement.ConnectorProcessGeneration = old.ConnectorProcessGeneration + 1
	replacement.EdgeProcessEpoch = "epoch_new_0002"
	newID := tunnelEdgeRouteAssignmentID(replacement, 2)
	if newID == oldID {
		t.Fatalf("process replacement reused assignment ID %q", newID)
	}
	newStaged := trk35RouteAssignmentRow(replacement, newID, 2, "staged", "")
	newReady := trk35RouteAssignmentRow(replacement, newID, 2, "active", "ready")

	oldRequest := trk35RouteAssignmentRequest(old, oldID, 1)
	newRequest := trk35RouteAssignmentRequest(replacement, newID, 2)
	if err := validateTunnelEdgeRouteAssignmentRequest(oldRequest); err != nil {
		t.Fatalf("old assignment request invalid: %v", err)
	}
	if err := validateTunnelEdgeRouteAssignmentRequest(newRequest); err != nil {
		t.Fatalf("replacement assignment request invalid: %v", err)
	}

	// A failed or delayed replacement must leave the old route available while
	// the new row is staged. The registry key is the immutable assignment ID,
	// rather than route_id, so both handoff rows can coexist safely.
	lkg := map[string]map[string]any{oldID: tunnelEdgeRouteJSON(oldRow)}
	lkg[newID] = tunnelEdgeRouteJSON(newStaged)
	if len(lkg) != 2 {
		t.Fatalf("handoff registry size = %d, want old and staged replacement", len(lkg))
	}
	if got := lkg[oldID]["edge_process_epoch"]; got != old.EdgeProcessEpoch {
		t.Fatalf("old LKG epoch = %v, want %q", got, old.EdgeProcessEpoch)
	}
	if got := lkg[newID]["edge_process_epoch"]; got != replacement.EdgeProcessEpoch {
		t.Fatalf("staged replacement epoch = %v, want %q", got, replacement.EdgeProcessEpoch)
	}

	// This is the late callback from the replaced process. It identifies the
	// old assignment, so finalizing that row cannot touch the replacement key.
	lateOld := RouteObservation{
		RouteID: old.RouteID, AssignmentID: oldID, AssignmentGeneration: 1,
		RouteRevision: 1, EdgeNodeID: old.EdgeNodeID, EdgeProcessEpoch: old.EdgeProcessEpoch,
		ConnectorID: old.ConnectorID, HostID: old.HostID, ConnectorGeneration: old.ConnectorGeneration,
		ConnectorSessionID: old.ConnectorSessionID.String, ConnectorProcessGeneration: old.ConnectorProcessGeneration,
		ConfigGeneration: old.ConfigGeneration, ConfigContentHash: "sha256:" + "3535353535353535353535353535353535353535353535353535353535353535",
		ObservedState: "detached",
	}
	if lateOld.AssignmentID == newID || lateOld.EdgeProcessEpoch == replacement.EdgeProcessEpoch || lateOld.ConnectorSessionID == replacement.ConnectorSessionID.String {
		t.Fatal("late old callback unexpectedly carries replacement fence")
	}
	delete(lkg, lateOld.AssignmentID)
	if _, present := lkg[newID]; !present {
		t.Fatal("late old callback erased staged replacement")
	}

	// Readiness promotes the replacement in place. Its session, process epoch,
	// and connector process generation remain visible in the LKG projection.
	lkg[newID] = tunnelEdgeRouteJSON(newReady)
	if len(lkg) != 1 {
		t.Fatalf("post-handoff registry size = %d, want one replacement", len(lkg))
	}
	projection := lkg[newID]
	for key, want := range map[string]any{
		"assignment_generation":        int64(2),
		"connector_session_id":         replacement.ConnectorSessionID.String,
		"connector_process_generation": replacement.ConnectorProcessGeneration,
		"edge_process_epoch":           replacement.EdgeProcessEpoch,
		"observed_state":               "ready",
	} {
		if got := projection[key]; got != want {
			t.Fatalf("replacement projection %s = %v, want %v", key, got, want)
		}
	}
}

func trk35RouteAssignmentRow(candidate dbsqlc.ListReadyTunnelEdgeRouteCandidatesV1Row, assignmentID string, assignmentGeneration int64, state, observedState string) dbsqlc.ListTunnelEdgeRouteAssignmentsForNodeV1Row {
	return dbsqlc.ListTunnelEdgeRouteAssignmentsForNodeV1Row{
		AssignmentID: assignmentID, AssignmentGeneration: assignmentGeneration,
		RouteID: candidate.RouteID, RouteRevision: candidate.RouteGeneration,
		AccountID: candidate.AccountID, TunnelID: candidate.TunnelID, ConnectorID: candidate.ConnectorID,
		HostID: candidate.HostID, MachineIdentityPublicKey: candidate.MachineIdentityPublicKey.String,
		ConnectorGeneration: candidate.ConnectorGeneration, ConnectorSessionID: candidate.ConnectorSessionID.String,
		ConnectorProcessGeneration: candidate.ConnectorProcessGeneration, ConfigGeneration: candidate.ConfigGeneration,
		ConfigContentHash: append([]byte(nil), candidate.ConfigContentHash...), EdgeNodeID: candidate.EdgeNodeID,
		EdgeProcessEpoch: candidate.EdgeProcessEpoch, Kind: "tunnel_http_wss", PublicHost: "trk35.example.test",
		MatchType: "exact", MatchHostname: sql.NullString{String: "trk35.example.test", Valid: true},
		Priority: 10, Protocol: "http", OriginScheme: "http", PreserveHost: true,
		DomainBindings: "[]", State: state, ObservedState: observedState, RouteDesiredState: "active",
	}
}

func trk35RouteAssignmentRequest(candidate dbsqlc.ListReadyTunnelEdgeRouteCandidatesV1Row, assignmentID string, assignmentGeneration int64) TunnelEdgeRouteAssignmentRequest {
	return TunnelEdgeRouteAssignmentRequest{
		AssignmentID: assignmentID, AssignmentGeneration: assignmentGeneration,
		AccountID: candidate.AccountID, TunnelID: candidate.TunnelID, ConnectorID: candidate.ConnectorID,
		ConnectorGeneration: candidate.ConnectorGeneration, ConnectorSessionID: candidate.ConnectorSessionID.String,
		ConnectorProcessGeneration: candidate.ConnectorProcessGeneration, ConfigGeneration: candidate.ConfigGeneration,
		ConfigContentHash: append([]byte(nil), candidate.ConfigContentHash...), EdgeNodeID: candidate.EdgeNodeID,
		EdgeProcessEpoch: candidate.EdgeProcessEpoch, RouteID: candidate.RouteID,
	}
}

func TestTRK35StaleControlWorkerCompletionReportsLeaseLoss(t *testing.T) {
	storageErr := errors.New("storage unavailable")
	for _, test := range []struct {
		name    string
		updated int64
		err     error
		want    error
	}{
		{name: "newer worker won", updated: 0, want: ErrOperationLeaseLost},
		{name: "owner completed", updated: 1},
		{name: "duplicate affected rows", updated: 2},
		{name: "storage error", updated: 0, err: storageErr, want: storageErr},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := operationUpdateResult(test.updated, test.err); !errors.Is(got, test.want) {
				t.Fatalf("operation result = %v, want %v", got, test.want)
			}
		})
	}
}
