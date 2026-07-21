package orchestrator

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
	"github.com/pinksaucepasta/paperboat-server/internal/fly"
)

var ErrProviderOperationConflict = errors.New("provider operation step already reserved with different request")

type orchestrationJobContextKey struct{}

type ProviderOperation = dbsqlc.HostedProviderOperation

func (r *Repository) ReserveProviderOperation(ctx context.Context, jobID, step, resourceType string, requestHash []byte) (ProviderOperation, error) {
	operation, err := r.db.Queries().ReserveHostedProviderOperation(ctx, dbsqlc.ReserveHostedProviderOperationParams{
		ID: newID("hop"), OrchestrationJobID: jobID, Step: step, ResourceType: resourceType, RequestHash: requestHash,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return ProviderOperation{}, ErrProviderOperationConflict
	}
	return operation, err
}

func (r *Repository) StartProviderOperation(ctx context.Context, operationID string) error {
	return r.db.Queries().StartHostedProviderOperation(ctx, operationID)
}

func (r *Repository) ResetProviderOperationAfterAbsentObservation(ctx context.Context, operationID string) error {
	return r.db.Queries().ResetHostedProviderOperationAfterAbsentObservation(ctx, operationID)
}

func (r *Repository) CompleteProviderOperation(ctx context.Context, operationID, providerRequestID string) error {
	return r.db.Queries().CompleteHostedProviderOperation(ctx, dbsqlc.CompleteHostedProviderOperationParams{ID: operationID, ProviderRequestID: providerRequestID})
}

func (r *Repository) ResolveProviderOperationByObservation(ctx context.Context, operationID, providerRequestID string) error {
	return r.db.Queries().ResolveHostedProviderOperationByObservation(ctx, dbsqlc.ResolveHostedProviderOperationByObservationParams{ID: operationID, ProviderRequestID: providerRequestID})
}

func (r *Repository) ProviderOperationSucceeded(ctx context.Context, step string) (bool, error) {
	jobID, ok := ctx.Value(orchestrationJobContextKey{}).(string)
	if !ok || jobID == "" {
		return false, nil
	}
	return r.db.Queries().ProviderOperationSucceeded(ctx, dbsqlc.ProviderOperationSucceededParams{OrchestrationJobID: jobID, Step: step})
}

func executeProviderMutation[T any](ctx context.Context, repo *Repository, step, resourceType string, request any, mutate func() (T, error)) (T, error) {
	var zero T
	jobID, ok := ctx.Value(orchestrationJobContextKey{}).(string)
	if !ok || jobID == "" {
		// Direct service-method calls are retained for package tests. Production
		// lifecycle execution enters through RunOnce and always supplies a job.
		return mutate()
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		return zero, fmt.Errorf("encode provider operation request: %w", err)
	}
	hash := sha256.Sum256(encoded)
	operation, err := repo.ReserveProviderOperation(ctx, jobID, step, resourceType, hash[:])
	if err != nil {
		return zero, err
	}
	// The caller reaches this point only after its tagged-resource lookup proved
	// the requested resource absent. That observation resolves a prior ambiguous
	// create before another attempt is permitted.
	if operation.State == "running" || operation.State == "uncertain" || operation.State == "succeeded" {
		if err := repo.ResetProviderOperationAfterAbsentObservation(ctx, operation.ID); err != nil {
			return zero, err
		}
	} else if operation.State == "failed" {
		return zero, &fly.ProviderError{Outcome: fly.Outcome(operation.Outcome), Operation: step, RequestID: operation.ProviderRequestID, Cause: errors.New(operation.LastError)}
	}
	if err := repo.StartProviderOperation(ctx, operation.ID); err != nil {
		return zero, err
	}
	result, mutationErr := mutate()
	if mutationErr != nil {
		if recordErr := repo.FailProviderOperation(ctx, operation.ID, mutationErr); recordErr != nil {
			return zero, errors.Join(mutationErr, recordErr)
		}
		return zero, mutationErr
	}
	if err := repo.CompleteProviderOperation(ctx, operation.ID, ""); err != nil {
		return zero, err
	}
	return result, nil
}

func resolveProviderMutationByObservation(ctx context.Context, repo *Repository, step, resourceType string, request any, providerRequestID string) error {
	jobID, ok := ctx.Value(orchestrationJobContextKey{}).(string)
	if !ok || jobID == "" {
		return nil
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("encode provider operation observation: %w", err)
	}
	hash := sha256.Sum256(encoded)
	operation, err := repo.ReserveProviderOperation(ctx, jobID, step, resourceType, hash[:])
	if err != nil {
		return err
	}
	return repo.ResolveProviderOperationByObservation(ctx, operation.ID, providerRequestID)
}

func executeMachineMutation(ctx context.Context, repo *Repository, client fly.Client, step string, request any, machineID string, applied func(fly.Machine) bool, mutate func() (fly.Machine, error)) (fly.Machine, error) {
	jobID, ok := ctx.Value(orchestrationJobContextKey{}).(string)
	if !ok || jobID == "" {
		return mutate()
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		return fly.Machine{}, fmt.Errorf("encode machine operation request: %w", err)
	}
	hash := sha256.Sum256(encoded)
	operation, err := repo.ReserveProviderOperation(ctx, jobID, step, "machine", hash[:])
	if err != nil {
		return fly.Machine{}, err
	}
	if operation.State != "pending" {
		observed, observeErr := client.GetMachine(ctx, machineID)
		if observeErr != nil {
			return fly.Machine{}, observeErr
		}
		if applied(observed) {
			if err := repo.ResolveProviderOperationByObservation(ctx, operation.ID, ""); err != nil {
				return fly.Machine{}, err
			}
			return observed, nil
		}
		if operation.State == "failed" {
			if fly.Outcome(operation.Outcome) != fly.OutcomeConflict {
				return fly.Machine{}, &fly.ProviderError{Outcome: fly.Outcome(operation.Outcome), Operation: step, RequestID: operation.ProviderRequestID, Cause: errors.New(operation.LastError)}
			}
		}
		if err := repo.ResetProviderOperationAfterAbsentObservation(ctx, operation.ID); err != nil {
			return fly.Machine{}, err
		}
	}
	if err := repo.StartProviderOperation(ctx, operation.ID); err != nil {
		return fly.Machine{}, err
	}
	result, mutationErr := mutate()
	if mutationErr != nil {
		if recordErr := repo.FailProviderOperation(ctx, operation.ID, mutationErr); recordErr != nil {
			return fly.Machine{}, errors.Join(mutationErr, recordErr)
		}
		return fly.Machine{}, mutationErr
	}
	if err := repo.CompleteProviderOperation(ctx, operation.ID, ""); err != nil {
		return fly.Machine{}, err
	}
	return result, nil
}

func executeDestroyMutation(ctx context.Context, repo *Repository, step, resourceType string, request any, observe func() error, mutate func() error) error {
	jobID, ok := ctx.Value(orchestrationJobContextKey{}).(string)
	if !ok || jobID == "" {
		return mutate()
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("encode destroy operation request: %w", err)
	}
	hash := sha256.Sum256(encoded)
	operation, err := repo.ReserveProviderOperation(ctx, jobID, step, resourceType, hash[:])
	if err != nil {
		return err
	}
	if operation.State == "failed" {
		return &fly.ProviderError{Outcome: fly.Outcome(operation.Outcome), Operation: step, RequestID: operation.ProviderRequestID, Cause: errors.New(operation.LastError)}
	}
	if operation.State != "pending" {
		observeErr := observe()
		if errors.Is(observeErr, fly.ErrNotFound) {
			return repo.ResolveProviderOperationByObservation(ctx, operation.ID, "")
		}
		if observeErr != nil {
			return observeErr
		}
		if err := repo.ResetProviderOperationAfterAbsentObservation(ctx, operation.ID); err != nil {
			return err
		}
	}
	if err := repo.StartProviderOperation(ctx, operation.ID); err != nil {
		return err
	}
	mutationErr := mutate()
	if errors.Is(mutationErr, fly.ErrNotFound) {
		return repo.ResolveProviderOperationByObservation(ctx, operation.ID, "")
	}
	if mutationErr != nil {
		if recordErr := repo.FailProviderOperation(ctx, operation.ID, mutationErr); recordErr != nil {
			return errors.Join(mutationErr, recordErr)
		}
		return mutationErr
	}
	return repo.CompleteProviderOperation(ctx, operation.ID, "")
}

func executeNonObservableMutation(ctx context.Context, repo *Repository, step, resourceType string, request any, mutate func() error) error {
	jobID, ok := ctx.Value(orchestrationJobContextKey{}).(string)
	if !ok || jobID == "" {
		return mutate()
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("encode provider operation request: %w", err)
	}
	hash := sha256.Sum256(encoded)
	operation, err := repo.ReserveProviderOperation(ctx, jobID, step, resourceType, hash[:])
	if err != nil {
		return err
	}
	switch operation.State {
	case "succeeded":
		return nil
	case "running", "uncertain":
		return &fly.ProviderError{Outcome: fly.OutcomeUncertain, Operation: step, RequestID: operation.ProviderRequestID, Cause: errors.New("provider outcome requires operator observation")}
	case "failed":
		return &fly.ProviderError{Outcome: fly.Outcome(operation.Outcome), Operation: step, RequestID: operation.ProviderRequestID, Cause: errors.New(operation.LastError)}
	}
	if err := repo.StartProviderOperation(ctx, operation.ID); err != nil {
		return err
	}
	mutationErr := mutate()
	if errors.Is(mutationErr, fly.ErrNotFound) {
		return repo.ResolveProviderOperationByObservation(ctx, operation.ID, "")
	}
	if mutationErr != nil {
		if recordErr := repo.FailProviderOperation(ctx, operation.ID, mutationErr); recordErr != nil {
			return errors.Join(mutationErr, recordErr)
		}
		return mutationErr
	}
	return repo.CompleteProviderOperation(ctx, operation.ID, "")
}

func (r *Repository) FailProviderOperation(ctx context.Context, operationID string, cause error) error {
	outcome := fly.OutcomePermanent
	requestID := ""
	var providerErr *fly.ProviderError
	if errors.As(cause, &providerErr) {
		outcome = providerErr.Outcome
		requestID = providerErr.RequestID
	}
	lastError := "provider operation failed"
	if cause != nil {
		lastError = cause.Error()
	}
	if err := r.db.Queries().FailHostedProviderOperation(ctx, dbsqlc.FailHostedProviderOperationParams{
		ID: operationID, Outcome: string(outcome), ProviderRequestID: requestID, LastError: lastError, Uncertain: outcome == fly.OutcomeUncertain,
	}); err != nil {
		return err
	}
	return nil
}
