package workers

import (
	"context"
	"sync"
)

type Worker func(context.Context) error

type Supervisor struct {
	workers []Worker
}

func NewSupervisor(workers ...Worker) *Supervisor {
	return &Supervisor{workers: workers}
}

func (s *Supervisor) Run(ctx context.Context) error {
	if len(s.workers) == 0 {
		<-ctx.Done()
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
