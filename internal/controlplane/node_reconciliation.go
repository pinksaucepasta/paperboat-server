package controlplane

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
	"github.com/pinksaucepasta/paperboat-server/internal/observability"
)

func ControlTunnelNodeStaleAfter() time.Duration {
	return controlTunnelNodeStaleAfter
}

// ReconcileStaleNodes fences nodes that missed their heartbeat deadline. All
// connector and route mutations happen in the same transaction as the stale
// observation, so a newer heartbeat/reassignment cannot be deleted by this run.
func (s *EdgeService) ReconcileStaleNodes(ctx context.Context, cutoff time.Time, batchSize int) (int, error) {
	if s.store == nil {
		return 0, nil
	}
	if batchSize <= 0 || batchSize > 100 {
		batchSize = 25
	}
	count := 0
	err := s.store.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		nodes, err := tx.Queries().ListStaleControlTunnelNodesForUpdate(ctx, dbsqlc.ListStaleControlTunnelNodesForUpdateParams{Cutoff: sql.NullTime{Time: cutoff, Valid: true}, BatchSize: int32(batchSize)})
		if err != nil {
			return err
		}
		now := s.clock().UTC()
		for _, node := range nodes {
			if rows, err := tx.Queries().MarkControlTunnelNodeOffline(ctx, dbsqlc.MarkControlTunnelNodeOfflineParams{ID: node.ID, ExpectedVersion: node.Version, Now: now}); err != nil {
				return err
			} else if rows != 1 {
				continue
			}
			nodeID := sql.NullString{String: node.ID, Valid: true}
			if _, err := tx.Queries().FenceControlConnectorsForNode(ctx, dbsqlc.FenceControlConnectorsForNodeParams{EdgeNodeID: nodeID, Now: now}); err != nil {
				return err
			}
			if _, err := tx.Queries().AdvanceControlRoutesForNodeLoss(ctx, dbsqlc.AdvanceControlRoutesForNodeLossParams{EdgeNodeID: nodeID, Now: now}); err != nil {
				return err
			}
			if err := s.audit.WriteTx(ctx, tx, audit.Event{ActorType: audit.ActorSystem, EventType: "edge.node_stale", ResourceType: "edge_node", ResourceID: node.ID, IdempotencyKey: fmt.Sprintf("edge.node_stale:%s:%d", node.ID, node.Version), Metadata: map[string]any{"cutoff": cutoff}}); err != nil {
				return err
			}
			count++
		}
		return nil
	})
	if err == nil {
		observability.ControlNodeStale(int64(count))
	}
	return count, err
}

func (s *EdgeService) StaleNodeWorker(interval, staleAfter time.Duration) func(context.Context) error {
	if interval <= 0 {
		interval = time.Second
	}
	if staleAfter <= 0 {
		staleAfter = 2 * interval
	}
	return func(ctx context.Context) error {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			_, _ = s.ReconcileStaleNodes(ctx, s.clock().UTC().Add(-staleAfter), 25)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-ticker.C:
			}
		}
	}
}
