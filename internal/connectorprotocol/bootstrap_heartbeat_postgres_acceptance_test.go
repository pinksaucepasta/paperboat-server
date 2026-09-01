package connectorprotocol

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"
)

// TestTRK08PostgresHeartbeatRenewsAwaitingReadiness exercises the durable
// bootstrap contract that lets a connector stay authenticated while the edge
// carrier and route are still being prepared. The test deliberately leaves the
// session unready for more than two heartbeat intervals, then checks that
// invalid/replayed heartbeats cannot advance the durable timestamp fence before
// completing the exact readiness transition.
func TestTRK08PostgresHeartbeatRenewsAwaitingReadiness(t *testing.T) {
	f := newTRK08PostgresFixture(t)
	ctx := context.Background()
	connector := f.insertConnector(t, "heartbeat", false)
	sessionID := "sess_trk08_" + f.suffix + "_heartbeat"
	ref := SessionRef{
		TunnelID:          f.tunnelID,
		ConnectorID:       connector.id,
		SessionID:         sessionID,
		ProcessGeneration: 1,
	}

	server, err := NewPersistentServer(f.store, f.store, ServerConfig{
		Capabilities:      ProductionCapabilities(),
		Clock:             f.clock,
		LeaseDuration:     30 * time.Minute,
		HeartbeatInterval: 10 * time.Second,
		SessionIDs: func() (string, error) {
			return sessionID, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	auth := f.authRequest(connector, 1, connector.oldIdentityKeyID, connector.oldThumbprint, connector.oldPrivate, "heartbeat-auth-"+f.suffix)
	hello := Hello{
		Protocol:          ProtocolName,
		MinVersion:        ProtocolVersion,
		MaxVersion:        ProtocolVersion,
		AccountID:         f.accountID,
		TunnelID:          f.tunnelID,
		ConnectorID:       connector.id,
		HostID:            connector.hostID,
		ProcessGeneration: ref.ProcessGeneration,
		Capabilities:      ProductionCapabilities(),
		Auth:              auth,
	}
	session, welcome, snapshot, err := server.Accept(ctx, hello)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = session.Close(context.Background(), ReasonProtocolClosed)
	})
	if session.Reference() != ref || welcome.SessionID != sessionID {
		t.Fatalf("session binding = ref=%+v welcome=%+v want=%+v/%s", session.Reference(), welcome, ref, sessionID)
	}
	if err := session.HandleAck(ctx, Ack{
		AccountID:         f.accountID,
		TunnelID:          ref.TunnelID,
		ConnectorID:       ref.ConnectorID,
		SessionID:         ref.SessionID,
		ProcessGeneration: ref.ProcessGeneration,
		Kind:              AckSnapshot,
		Status:            AckApplied,
		Generation:        snapshot.Generation,
		ContentHash:       snapshot.ContentHash,
	}); err != nil {
		t.Fatalf("persist initial snapshot ACK: %v", err)
	}
	if session.session.State() != SessionAwaitingReady {
		t.Fatalf("in-memory state after snapshot ACK=%s, want %s", session.session.State(), SessionAwaitingReady)
	}
	if current, ready, generation := session.Current(); ready || generation != 0 || current.Generation != 0 {
		t.Fatalf("session promoted before readiness: current=%+v ready=%t generation=%d", current, ready, generation)
	}
	initial := readTRK08HeartbeatState(t, f, ref)
	assertTRK08AwaitingReady(t, initial, snapshot.Generation)

	base := f.clock.now
	heartbeatInterval := 10 * time.Second
	lastLease := initial.leaseDeadline
	for index, offset := range []time.Duration{heartbeatInterval, 2 * heartbeatInterval, 3 * heartbeatInterval, 4 * heartbeatInterval} {
		f.clock.now = base.Add(offset)
		heartbeat := trk08CandidateHeartbeat(ref, f.accountID, snapshot, f.clock.now)
		ack, err := session.HandleHeartbeat(ctx, heartbeat)
		if err != nil {
			t.Fatalf("heartbeat %d at %s: %v", index+1, f.clock.now.Format(time.RFC3339), err)
		}
		if ack.LeaseExpiresAt.Before(f.clock.now.Add(30*time.Minute)) || !ack.LeaseExpiresAt.Equal(f.clock.now.Add(30*time.Minute)) {
			t.Fatalf("heartbeat %d lease=%s, want %s", index+1, ack.LeaseExpiresAt, f.clock.now.Add(30*time.Minute))
		}
		state := readTRK08HeartbeatState(t, f, ref)
		assertTRK08AwaitingReady(t, state, snapshot.Generation)
		if !state.lastHeartbeat.Equal(f.clock.now) || !state.lastSent.Valid || !state.lastSent.Time.Equal(heartbeat.SentAt) {
			t.Fatalf("heartbeat %d durable timestamps: %+v heartbeat=%s", index+1, state, heartbeat.SentAt)
		}
		if !state.leaseDeadline.After(lastLease) {
			t.Fatalf("heartbeat %d did not advance lease: previous=%s current=%s", index+1, lastLease, state.leaseDeadline)
		}
		lastLease = state.leaseDeadline
	}

	// Each rejected heartbeat is attempted against the exact current session.
	// Capture the durable fence before every attempt so a malformed or replayed
	// timestamp cannot poison the next valid candidate.
	beforeInvalid := readTRK08HeartbeatState(t, f, ref)
	f.clock.now = base.Add(4*heartbeatInterval + time.Second)
	badGeneration := trk08CandidateHeartbeat(ref, f.accountID, snapshot, f.clock.now)
	badGeneration.LastAppliedGeneration = snapshot.Generation + 999
	badGeneration.LastAppliedHash = snapshot.ContentHash
	if err := f.store.RecordHeartbeat(ctx, ref, badGeneration, trk08HeartbeatAck(ref, f.accountID, f.clock.now)); !errors.Is(err, ErrConfigNotFound) {
		t.Fatalf("mismatched generation error=%v, want %v", err, ErrConfigNotFound)
	}
	assertTRK08HeartbeatFenceUnchanged(t, beforeInvalid, readTRK08HeartbeatState(t, f, ref), "mismatched generation")

	beforeInvalid = readTRK08HeartbeatState(t, f, ref)
	f.clock.now = base.Add(4*heartbeatInterval + 2*time.Second)
	badHash := trk08CandidateHeartbeat(ref, f.accountID, snapshot, f.clock.now)
	badHash.LastAppliedHash = "sha256:" + strings.Repeat("b", 64)
	if err := f.store.RecordHeartbeat(ctx, ref, badHash, trk08HeartbeatAck(ref, f.accountID, f.clock.now)); !errors.Is(err, ErrSnapshotRequired) {
		t.Fatalf("mismatched hash error=%v, want %v", err, ErrSnapshotRequired)
	}
	assertTRK08HeartbeatFenceUnchanged(t, beforeInvalid, readTRK08HeartbeatState(t, f, ref), "mismatched hash")

	beforeInvalid = readTRK08HeartbeatState(t, f, ref)
	f.clock.now = base.Add(4*heartbeatInterval + 3*time.Second)
	replay := trk08CandidateHeartbeat(ref, f.accountID, snapshot, f.clock.now)
	replay.SentAt = base.Add(4 * heartbeatInterval)
	if err := f.store.RecordHeartbeat(ctx, ref, replay, trk08HeartbeatAck(ref, f.accountID, f.clock.now)); !errors.Is(err, ErrDurableReplay) {
		t.Fatalf("replayed timestamp error=%v, want %v", err, ErrDurableReplay)
	}
	assertTRK08HeartbeatFenceUnchanged(t, beforeInvalid, readTRK08HeartbeatState(t, f, ref), "replayed timestamp")

	// One final valid heartbeat keeps the in-memory session inside its timeout
	// window before the readiness transition. It must still be candidate-only.
	f.clock.now = base.Add(4*heartbeatInterval + 4*time.Second)
	if _, err := session.HandleHeartbeat(ctx, trk08CandidateHeartbeat(ref, f.accountID, snapshot, f.clock.now)); err != nil {
		t.Fatalf("final candidate heartbeat: %v", err)
	}
	if session.session.State() != SessionAwaitingReady {
		t.Fatalf("state after candidate heartbeats=%s, want %s", session.session.State(), SessionAwaitingReady)
	}

	readyAck, err := session.HandleReadiness(ctx, Readiness{
		AccountID:         f.accountID,
		TunnelID:          ref.TunnelID,
		ConnectorID:       ref.ConnectorID,
		SessionID:         ref.SessionID,
		ProcessGeneration: ref.ProcessGeneration,
		Generation:        snapshot.Generation,
		ContentHash:       snapshot.ContentHash,
		EdgeReady:         true,
		RouteReady:        true,
		OriginReady:       true,
	})
	if err != nil {
		t.Fatalf("exact readiness: %v", err)
	}
	if readyAck.Kind != AckReady || readyAck.Status != AckApplied {
		t.Fatalf("readiness ACK=%+v, want applied ready", readyAck)
	}
	final := readTRK08HeartbeatState(t, f, ref)
	if final.state != "ready" || !final.sessionReady.Valid || !final.connectorReady.Valid || final.appliedGeneration != int64(snapshot.Generation) || final.connectorAppliedGeneration != int64(snapshot.Generation) {
		t.Fatalf("durable ready state=%+v", final)
	}
	if session.session.State() != SessionReady {
		t.Fatalf("in-memory state after readiness=%s, want %s", session.session.State(), SessionReady)
	}
}

type trk08HeartbeatState struct {
	state                      string
	sessionReady               sql.NullTime
	connectorReady             sql.NullTime
	appliedGeneration          int64
	connectorAppliedGeneration int64
	lastHeartbeat              time.Time
	lastSent                   sql.NullTime
	leaseDeadline              time.Time
}

func readTRK08HeartbeatState(t *testing.T, f *trk08PostgresFixture, ref SessionRef) trk08HeartbeatState {
	t.Helper()
	var state trk08HeartbeatState
	err := f.database.SQL().QueryRowContext(context.Background(), `
SELECT s.state, s.ready_at, c.ready_at,
       s.applied_config_generation, c.last_applied_config_generation,
       s.last_heartbeat_at, s.last_heartbeat_sent_at, s.lease_deadline
FROM paperboat.tunnel_connector_sessions AS s
JOIN paperboat.tunnel_connectors AS c ON c.id = s.connector_id
WHERE s.id = $1 AND s.connector_id = $2 AND s.process_generation = $3
  AND c.tunnel_id = $4`, ref.SessionID, ref.ConnectorID, int64(ref.ProcessGeneration), ref.TunnelID).Scan(
		&state.state,
		&state.sessionReady,
		&state.connectorReady,
		&state.appliedGeneration,
		&state.connectorAppliedGeneration,
		&state.lastHeartbeat,
		&state.lastSent,
		&state.leaseDeadline,
	)
	if err != nil {
		t.Fatalf("read heartbeat state: %v", err)
	}
	return state
}

func assertTRK08AwaitingReady(t *testing.T, state trk08HeartbeatState, generation uint64) {
	t.Helper()
	if state.state != "authenticating" || state.sessionReady.Valid || state.connectorReady.Valid || state.appliedGeneration != int64(generation) || state.connectorAppliedGeneration != int64(generation) {
		t.Fatalf("session promoted before readiness: %+v", state)
	}
}

func assertTRK08HeartbeatFenceUnchanged(t *testing.T, before, after trk08HeartbeatState, reason string) {
	t.Helper()
	if before.state != after.state || !before.lastHeartbeat.Equal(after.lastHeartbeat) || before.lastSent.Valid != after.lastSent.Valid || before.lastSent.Valid && !before.lastSent.Time.Equal(after.lastSent.Time) || !before.leaseDeadline.Equal(after.leaseDeadline) {
		t.Fatalf("%s advanced durable heartbeat fence: before=%+v after=%+v", reason, before, after)
	}
}

func trk08CandidateHeartbeat(ref SessionRef, accountID string, snapshot Snapshot, sentAt time.Time) Heartbeat {
	return Heartbeat{
		AccountID:             accountID,
		SessionID:             ref.SessionID,
		TunnelID:              ref.TunnelID,
		ConnectorID:           ref.ConnectorID,
		ProcessGeneration:     ref.ProcessGeneration,
		LastAppliedGeneration: snapshot.Generation,
		LastAppliedHash:       snapshot.ContentHash,
		SentAt:                sentAt,
	}
}

func trk08HeartbeatAck(ref SessionRef, accountID string, now time.Time) HeartbeatAck {
	return HeartbeatAck{
		AccountID:         accountID,
		TunnelID:          ref.TunnelID,
		ConnectorID:       ref.ConnectorID,
		SessionID:         ref.SessionID,
		ProcessGeneration: ref.ProcessGeneration,
		LeaseExpiresAt:    now.Add(30 * time.Minute),
		ServerTime:        now,
	}
}
