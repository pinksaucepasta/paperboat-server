package usermachines

import (
	"errors"
	"testing"
	"time"
)

func validUpdateObservation() UpdateObservation {
	return UpdateObservation{
		Schema: UpdateObservationSchemaV1, State: "healthy", CurrentVersion: "2026.08.18.1",
		Channel: "stable", OperationID: "update-op-0001", InstallationGeneration: 2,
		WorkerGeneration: 4, OSBootID: "boot-1", RollbackCount: 0,
		ObservedAt: time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC),
	}
}

func TestUpdateObservationValidationFencesUnsafeState(t *testing.T) {
	observation := validUpdateObservation()
	if err := observation.Validate(observation.ObservedAt); err != nil {
		t.Fatalf("valid observation rejected: %v", err)
	}
	for name, mutate := range map[string]func(*UpdateObservation){
		"missing operation":               func(value *UpdateObservation) { value.OperationID = "short" },
		"failed without error":            func(value *UpdateObservation) { value.State = "failed" },
		"unknown error code":              func(value *UpdateObservation) { value.State, value.ErrorCode = "failed", "unsafe-value!" },
		"missing target while activating": func(value *UpdateObservation) { value.State = "activating" },
		"future timestamp":                func(value *UpdateObservation) { value.ObservedAt = time.Date(2026, 8, 18, 12, 6, 0, 0, time.UTC) },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := observation
			mutate(&candidate)
			if err := candidate.Validate(observation.ObservedAt); !errors.Is(err, ErrUpdateObservationInvalid) {
				t.Fatalf("validation error = %v", err)
			}
		})
	}
}

func TestUpdateObservationHashIsStable(t *testing.T) {
	observation := validUpdateObservation()
	if got, want := string(hashUpdateObservation(observation)), string(hashUpdateObservation(observation)); got != want {
		t.Fatal("equivalent observations produced different hashes")
	}
	changed := observation
	changed.WorkerGeneration++
	if string(hashUpdateObservation(observation)) == string(hashUpdateObservation(changed)) {
		t.Fatal("changed observation reused the same payload hash")
	}
}
