package workers

import (
	"context"
	"errors"
	"sync"
)

type Worker func(context.Context) error

type Supervisor struct {
	workers []Worker

	mu      sync.Mutex
	started bool
	ready   chan struct{}
	done    chan struct{}
}

func NewSupervisor(workers ...Worker) *Supervisor {
	return &Supervisor{workers: workers, ready: make(chan struct{}), done: make(chan struct{})}
}

var ErrSupervisorAlreadyStarted = errors.New("worker supervisor already started")

func (s *Supervisor) Run(ctx context.Context) error {
	if s == nil || ctx == nil {
		return context.Canceled
	}
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return ErrSupervisorAlreadyStarted
	}
	s.started = true
	close(s.ready)
	s.mu.Unlock()

	if len(s.workers) == 0 {
		<-ctx.Done()
		close(s.done)
		return ctx.Err()
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	errs := make(chan error, len(s.workers))
	for _, worker := range s.workers {
		worker := worker
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := worker(ctx); err != nil {
				errs <- err
			}
		}()
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
		close(s.done)
	}()

	select {
	case err := <-errs:
		if err != nil {
			cancel()
			return err
		}
	case <-done:
		return nil
	case <-ctx.Done():
		cancel()
		return ctx.Err()
	}
	return nil
}

// Wait blocks until every worker started by Run has returned. Run deliberately
// reports the first worker or parent-context failure promptly so callers can
// begin shutting down ingress; Wait is the ownership boundary that must finish
// before dependencies used by workers are closed.
func (s *Supervisor) Wait(ctx context.Context) error {
	if s == nil || ctx == nil {
		return context.Canceled
	}
	select {
	case <-s.ready:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-s.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
