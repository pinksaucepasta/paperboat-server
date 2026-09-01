package controlplane

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
)

const (
	defaultTunnelEdgeAssignmentBatch int32 = 100
	maxTunnelEdgeAssignmentBatch     int32 = 100
)

// ReconcileTunnelEdgeRouteAssignments publishes connector-ready HTTP and
// private TCP routes
// to one ready edge process.  Candidate selection and the immutable assignment
// write happen in one serializable transaction.  This makes a concurrent
// connector replacement, config activation, route mutation, or edge process
// replacement either win as a complete assignment or get retried by the next
// bounded pass.
func (s *EdgeService) ReconcileTunnelEdgeRouteAssignments(ctx context.Context, batchSize int32) (int, error) {
	if s == nil || s.store == nil {
		return 0, nil
	}
	if batchSize <= 0 || batchSize > maxTunnelEdgeAssignmentBatch {
		batchSize = defaultTunnelEdgeAssignmentBatch
	}
	now := s.clock().UTC()
	staged := 0
	err := s.store.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		candidates, err := tx.Queries().ListReadyTunnelEdgeRouteCandidatesV1(ctx, dbsqlc.ListReadyTunnelEdgeRouteCandidatesV1Params{
			Now: now, RowLimit: batchSize,
		})
		if err != nil {
			return err
		}
		attemptStaged := 0
		for _, candidate := range candidates {
			// The query currently filters this value through the session join, but
			// retain the validity check at the write boundary so a future query
			// change cannot turn a NULL session into an unbound assignment.
			if !candidate.ConnectorSessionID.Valid || !candidate.MachineIdentityPublicKey.Valid || len(candidate.ConfigContentHash) != sha256.Size {
				continue
			}
			machineThumbprint, err := canonicalMachineIdentityThumbprint(candidate.MachineIdentityPublicKey.String)
			if err != nil {
				continue
			}
			binding, err := tx.Queries().GetTunnelEdgeRouteAssignmentBindingV1(ctx, dbsqlc.GetTunnelEdgeRouteAssignmentBindingV1Params{
				RouteID: candidate.RouteID, AccountID: candidate.AccountID, TunnelID: candidate.TunnelID,
				ConnectorID: candidate.ConnectorID, HostID: candidate.HostID, ConnectorGeneration: candidate.ConnectorGeneration,
				ConnectorSessionID: candidate.ConnectorSessionID.String, ConnectorProcessGeneration: candidate.ConnectorProcessGeneration,
				ConfigGeneration: candidate.ConfigGeneration, ConfigContentHash: append([]byte(nil), candidate.ConfigContentHash...),
				EdgeNodeID: candidate.EdgeNodeID, EdgeProcessEpoch: candidate.EdgeProcessEpoch,
			})
			if err == nil {
				// A staged or active row with the exact immutable tuple is the
				// idempotent result of an earlier pass.
				_ = binding
				continue
			}
			if !errors.Is(err, sql.ErrNoRows) {
				return err
			}

			nextGeneration, err := tx.Queries().NextTunnelEdgeRouteAssignmentGenerationV1(ctx, candidate.RouteID)
			if err != nil {
				return err
			}
			if nextGeneration < 1 {
				return fmt.Errorf("invalid next tunnel edge assignment generation %d", nextGeneration)
			}
			assignmentID := tunnelEdgeRouteAssignmentID(candidate, nextGeneration)
			_, err = tx.Queries().StageTunnelEdgeRouteAssignmentV1(ctx, dbsqlc.StageTunnelEdgeRouteAssignmentV1Params{
				AssignmentID: assignmentID, AssignmentGeneration: nextGeneration, Now: now,
				AccountID: candidate.AccountID, ConnectorID: candidate.ConnectorID,
				ConnectorSessionID: candidate.ConnectorSessionID.String, ConfigGeneration: candidate.ConfigGeneration,
				MachineIdentityThumbprint: machineThumbprint,
				EdgeNodeID:                candidate.EdgeNodeID, EdgeProcessEpoch: candidate.EdgeProcessEpoch,
				RouteID: candidate.RouteID, TunnelID: candidate.TunnelID,
				ConnectorGeneration: candidate.ConnectorGeneration, ConnectorProcessGeneration: candidate.ConnectorProcessGeneration,
				ConfigContentHash: append([]byte(nil), candidate.ConfigContentHash...),
			})
			if errors.Is(err, sql.ErrNoRows) {
				// The candidate became stale or another assignment is staged
				// during this bounded pass.  Leave it for the next pass.
				continue
			}
			if err != nil {
				return err
			}
			if s.audit != nil {
				if err := s.audit.WriteTx(ctx, tx, audit.Event{
					ActorType: audit.ActorSystem, EventType: "edge.route_assignment_staged",
					ResourceType: "tunnel_edge_route_assignment", ResourceID: assignmentID,
					IdempotencyKey: "edge.route_assignment.staged:" + assignmentID,
					Metadata: map[string]any{
						"route_id": candidate.RouteID, "tunnel_id": candidate.TunnelID,
						"connector_id": candidate.ConnectorID, "connector_generation": candidate.ConnectorGeneration,
						"connector_session_id": candidate.ConnectorSessionID.String,
						"config_generation":    candidate.ConfigGeneration, "edge_node_id": candidate.EdgeNodeID,
						"edge_process_epoch": candidate.EdgeProcessEpoch, "assignment_generation": nextGeneration,
					},
				}); err != nil {
					return err
				}
			}
			attemptStaged++
		}
		staged = attemptStaged
		return nil
	})
	if err != nil {
		return 0, err
	}
	return staged, nil
}

// TunnelEdgeAssignmentWorker runs an immediate bounded reconciliation and
// then repeats it.  A transient database/provider failure is logged and left
// for the next pass so one failed observation cannot take down all server
// workers or erase the edge's last-known-good state.
func (s *EdgeService) TunnelEdgeAssignmentWorker(interval time.Duration, batchSize int32) func(context.Context) error {
	if interval <= 0 {
		interval = time.Minute
	}
	if batchSize <= 0 || batchSize > maxTunnelEdgeAssignmentBatch {
		batchSize = defaultTunnelEdgeAssignmentBatch
	}
	return func(ctx context.Context) error {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			if _, err := s.ReconcileTunnelEdgeRouteAssignments(ctx, batchSize); err != nil && ctx.Err() == nil {
				slog.ErrorContext(ctx, "reconcile tunnel edge route assignments", "error", err)
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-ticker.C:
			}
		}
	}
}

func tunnelEdgeRouteAssignmentID(candidate dbsqlc.ListReadyTunnelEdgeRouteCandidatesV1Row, generation int64) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte("paperboat:tunnel-edge-assignment:v1"))
	writeAssignmentString(hash, candidate.AccountID)
	writeAssignmentString(hash, candidate.TunnelID)
	writeAssignmentString(hash, candidate.RouteID)
	writeAssignmentString(hash, candidate.ConnectorID)
	writeAssignmentString(hash, candidate.HostID)
	writeAssignmentString(hash, candidate.ConnectorSessionID.String)
	writeAssignmentString(hash, candidate.EdgeNodeID)
	writeAssignmentString(hash, candidate.EdgeProcessEpoch)
	writeAssignmentInt64(hash, candidate.ConnectorGeneration)
	writeAssignmentInt64(hash, candidate.ConnectorProcessGeneration)
	writeAssignmentInt64(hash, candidate.ConfigGeneration)
	writeAssignmentInt64(hash, generation)
	_, _ = hash.Write(candidate.ConfigContentHash)
	return "asn_" + hex.EncodeToString(hash.Sum(nil)[:24])
}

func writeAssignmentString(hash interface{ Write([]byte) (int, error) }, value string) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = hash.Write(length[:])
	_, _ = hash.Write([]byte(value))
}

func writeAssignmentInt64(hash interface{ Write([]byte) (int, error) }, value int64) {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], uint64(value))
	_, _ = hash.Write(encoded[:])
}
