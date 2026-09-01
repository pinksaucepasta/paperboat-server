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
	if err := supervisor.Wait(context.Background()); err != nil {
		t.Fatalf("wait for workers: %v", err)
	}
}

func TestSupervisorWithNoWorkersWaitsForContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := NewSupervisor().Run(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context canceled", err)
	}
	unstartedCtx, unstartedCancel := context.WithCancel(context.Background())
	unstartedCancel()
	if err := NewSupervisor().Wait(unstartedCtx); !errors.Is(err, context.Canceled) {
		t.Fatalf("unstarted wait error = %v, want context canceled", err)
	}
}

func TestSupervisorWaitJoinsWorkerAfterFirstError(t *testing.T) {
	want := errors.New("worker failed")
	release := make(chan struct{})
	workerCanceled := make(chan struct{})
	supervisor := NewSupervisor(
		func(context.Context) error { return want },
		func(ctx context.Context) error {
			<-ctx.Done()
			close(workerCanceled)
			<-release
			return nil
		},
	)

	if err := supervisor.Run(context.Background()); !errors.Is(err, want) {
		t.Fatalf("run error = %v, want %v", err, want)
	}
	<-workerCanceled
	waitCtx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := supervisor.Wait(waitCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("early wait error = %v, want deadline exceeded", err)
	}
	close(release)
	if err := supervisor.Wait(context.Background()); err != nil {
		t.Fatalf("joined wait error = %v", err)
	}
}
