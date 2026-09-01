package environment

import (
	"strings"
	"testing"
	"time"
)

func TestMarkMachineScopeAuthorizationRequiredClearsInitializedMetadata(t *testing.T) {
	observed := time.Unix(123, 0).UTC()
	view := ScopeView{
		Scope:                 ScopeMachine,
		MachineID:             "machine_01",
		ScopeState:            "retired",
		KeyState:              "ready",
		Version:               4,
		KeyEpoch:              2,
		ManifestID:            "sha256:" + strings.Repeat("a", 64),
		Variables:             []VariableMetadata{{Scope: ScopeMachine, MachineID: "machine_01", Name: "TOKEN", Configured: true, Version: 4, UpdatedAt: observed}},
		Status:                "applied",
		AppliedGlobalVersion:  3,
		AppliedMachineVersion: 4,
		AppliedState:          "applied",
		ErrorCode:             "stale_observation",
		ObservedAt:            &observed,
	}

	markMachineScopeAuthorizationRequired(&view)

	if view.Scope != ScopeMachine || view.MachineID != "machine_01" {
		t.Fatalf("identity changed: scope=%q machine_id=%q", view.Scope, view.MachineID)
	}
	if view.KeyState != "key_authorization_required" {
		t.Fatalf("key_state=%q, want key_authorization_required", view.KeyState)
	}
	if view.ScopeState != "" || view.Version != 0 || view.KeyEpoch != 0 || view.ManifestID != "" {
		t.Fatalf("initialized scope metadata was retained: %+v", view)
	}
	if view.Variables == nil || len(view.Variables) != 0 {
		t.Fatalf("variables=%v, want a non-nil empty list", view.Variables)
	}
	if view.Status != "" || view.AppliedGlobalVersion != 0 || view.AppliedMachineVersion != 0 || view.AppliedState != "" || view.ErrorCode != "" || view.ObservedAt != nil {
		t.Fatalf("delivery metadata was retained: %+v", view)
	}
}
