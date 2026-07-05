package workers

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestSupervisorReturnsFirstWorkerErrorAndCancelsSiblings(t *testing.T) {
	want := errors.New("worker failed")
	siblingCanceled := make(chan struct{})
	supervisor := NewSupervisor(
		func(context.Context) error {
			return want
		},
		func(ctx context.Context) error {
			<-ctx.Done()
			close(siblingCanceled)
			return nil
		},
	)
	err := supervisor.Run(context.Background())
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
	select {
	case <-siblingCanceled:
	case <-time.After(time.Second):
		t.Fatal("sibling worker was not canceled")
	}
}

func TestSupervisorWithNoWorkersWaitsForContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := NewSupervisor().Run(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context canceled", err)
	}
}
