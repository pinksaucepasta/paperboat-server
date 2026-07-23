package controlplane

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
	"github.com/pinksaucepasta/paperboat-server/internal/observability"
)

var (
	ErrInvalidUsageReport     = errors.New("invalid usage report")
	ErrUsageOperationConflict = errors.New("usage operation conflicts with an existing report")
)

type UsageReport struct {
	OperationID   string
	EdgeNodeID    string
	CounterEpoch  string
	EnvironmentID string
	RouteID       string
	RouteRevision int64
	Direction     string
	Bytes         int64
	IntervalStart time.Time
	IntervalEnd   time.Time
}

type UsageReceipt struct {
	OperationID   string
	DeltaBytes    int64
	ObservedBytes int64
	Duplicate     bool
}

type BandwidthDebiter interface {
	DebitEnvironmentBandwidthTx(context.Context, *db.Tx, string, int64, time.Time) (granted int64, exhausted bool, err error)
}

// ReconcileUsage persists an edge report and advances its absolute counter in one
// serializable transaction. It returns the original result for an exact operation
// retry, and never decreases a counter for a lower or delayed observation.
func ReconcileUsage(ctx context.Context, store *db.DB, report UsageReport, now time.Time) (UsageReceipt, error) {
	return reconcileUsage(ctx, store, report, now, nil)
}

func ReconcileUsageWithBandwidth(ctx context.Context, store *db.DB, report UsageReport, now time.Time, debiter BandwidthDebiter) (UsageReceipt, error) {
	return reconcileUsage(ctx, store, report, now, debiter)
}

func reconcileUsage(ctx context.Context, store *db.DB, report UsageReport, now time.Time, debiter BandwidthDebiter) (UsageReceipt, error) {
	if err := validateUsageReport(report); err != nil {
		return UsageReceipt{}, err
	}
	var result UsageReceipt
	err := store.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		existing, err := tx.Queries().GetControlUsageReceipt(ctx, report.OperationID)
		if err == nil {
			if !sameUsageReport(existing, report) {
				return ErrUsageOperationConflict
			}
			result = UsageReceipt{OperationID: report.OperationID, DeltaBytes: existing.DeltaBytes, ObservedBytes: existing.ObservedBytes, Duplicate: true}
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("look up usage receipt: %w", err)
		}

		previous, err := tx.Queries().GetControlUsageCounterForUpdate(ctx, dbsqlc.GetControlUsageCounterForUpdateParams{
			EdgeNodeID: report.EdgeNodeID, CounterEpoch: report.CounterEpoch, EnvironmentID: report.EnvironmentID,
			RouteID: report.RouteID, Direction: report.Direction,
		})
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("lock usage counter: %w", err)
		}
		var previousBytes int64
		if err == nil {
			previousBytes = previous.Bytes
		}
		delta := report.Bytes - previousBytes
		if delta < 0 {
			delta = 0
		}
		if _, err := tx.Queries().InsertControlUsageReceipt(ctx, dbsqlc.InsertControlUsageReceiptParams{
			OperationID: report.OperationID, EdgeNodeID: report.EdgeNodeID, CounterEpoch: report.CounterEpoch,
			EnvironmentID: report.EnvironmentID, RouteID: report.RouteID, RouteRevision: report.RouteRevision,
			Direction: report.Direction, ObservedBytes: report.Bytes, DeltaBytes: delta,
			IntervalStart: report.IntervalStart, IntervalEnd: report.IntervalEnd,
		}); err != nil {
			return fmt.Errorf("persist usage receipt: %w", err)
		}
		if debiter != nil && delta > 0 {
			_, exhausted, err := debiter.DebitEnvironmentBandwidthTx(ctx, tx, report.EnvironmentID, delta, now)
			if err != nil {
				return fmt.Errorf("debit bandwidth: %w", err)
			}
			if exhausted {
				if _, err := tx.Queries().SuspendControlEnvironmentForQuota(ctx, dbsqlc.SuspendControlEnvironmentForQuotaParams{ID: report.EnvironmentID, Now: now}); err != nil {
					return fmt.Errorf("suspend exhausted environment: %w", err)
				}
			}
		}
		if _, err := tx.Queries().UpsertControlUsageCounter(ctx, dbsqlc.UpsertControlUsageCounterParams{
			EdgeNodeID: report.EdgeNodeID, CounterEpoch: report.CounterEpoch, EnvironmentID: report.EnvironmentID,
			RouteID: report.RouteID, RouteRevision: report.RouteRevision, Direction: report.Direction,
			Bytes: report.Bytes, ObservedAt: report.IntervalEnd,
		}); err != nil {
			return fmt.Errorf("advance usage counter: %w", err)
		}
		result = UsageReceipt{OperationID: report.OperationID, DeltaBytes: delta, ObservedBytes: report.Bytes}
		return nil
	})
	if err == nil {
		observability.ControlUsageReceipt()
	}
	return result, err
}

func validateUsageReport(r UsageReport) error {
	for name, value := range map[string]string{"operation_id": r.OperationID, "edge_node_id": r.EdgeNodeID, "counter_epoch": r.CounterEpoch, "environment_id": r.EnvironmentID, "route_id": r.RouteID, "direction": r.Direction} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%w: %s is required", ErrInvalidUsageReport, name)
		}
	}
	if r.RouteRevision < 1 || r.Bytes < 0 || (r.Direction != "ingress" && r.Direction != "egress") {
		return fmt.Errorf("%w: invalid counter or direction", ErrInvalidUsageReport)
	}
	if r.IntervalStart.IsZero() || r.IntervalEnd.IsZero() || r.IntervalEnd.Before(r.IntervalStart) {
		return fmt.Errorf("%w: invalid interval", ErrInvalidUsageReport)
	}
	return nil
}

func sameUsageReport(existing dbsqlc.ControlUsageReceipt, r UsageReport) bool {
	return existing.EdgeNodeID == r.EdgeNodeID && existing.CounterEpoch == r.CounterEpoch &&
		existing.EnvironmentID == r.EnvironmentID && existing.RouteID == r.RouteID &&
		existing.RouteRevision == r.RouteRevision && existing.Direction == r.Direction &&
		existing.ObservedBytes == r.Bytes
}
