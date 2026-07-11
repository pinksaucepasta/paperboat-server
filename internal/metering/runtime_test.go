package metering_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/billing"
	"github.com/pinksaucepasta/paperboat-server/internal/config"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/fly"
	"github.com/pinksaucepasta/paperboat-server/internal/metering"
)

func TestRuntimeWorkerRetriesRunOnceErrorUntilContextDone(t *testing.T) {
	store, err := db.Open(config.Database{Driver: "postgres", DSN: "postgres://paperboat@127.0.0.1:1/paperboat?sslmode=disable"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	service := metering.NewRuntimeService(store, fly.NewFakeClient(), billing.NewRepository(store))
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	err = service.Worker(time.Hour)(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("worker error = %v, want context deadline after retrying RunOnce error", err)
	}
}

func TestRunOnceRetriesRevocationsDespiteMeteringFailure(t *testing.T) {
	store, err := db.Open(config.Database{Driver: "postgres", DSN: "postgres://paperboat@127.0.0.1:1/paperboat?sslmode=disable"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	revoker := &recordingRevoker{err: errors.New("revocation retry failed")}
	service := metering.NewRuntimeService(store, fly.NewFakeClient(), billing.NewRepository(store))
	service.SetDownstreamRevoker(revoker)
	err = service.RunOnce(context.Background())
	if err == nil || revoker.calls != 1 {
		t.Fatalf("RunOnce error=%v revocation calls=%d, want joined error and one call", err, revoker.calls)
	}
}

type recordingRevoker struct {
	calls int
	err   error
}

func (r *recordingRevoker) RetryPendingPapercodeRevocations(context.Context) error {
	r.calls++
	return r.err
}
