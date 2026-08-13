package codexsessions

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
	"github.com/pinksaucepasta/paperboat-server/internal/mint"
)

func TestDescriptorUsesPeerOnlyAuthorityAndCarriesMachineGeneration(t *testing.T) {
	provider, err := mint.New([]mint.Key{{ID: "codex-test", PrivateKey: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{'k'}, ed25519.SeedSize))}}, "codex-test", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	service := New(nil, provider, "https://api.paperboat.test", 1)
	service.now = func() time.Time { return time.Unix(2000, 0).UTC() }
	descriptor, err := service.descriptor(dbsqlc.CodexSession{ID: "cdx_1", EnvironmentID: "env_1", MachineID: "machine_1", UserID: "user_1", CLIClientSessionID: "cli_1", State: "ready", InstallationGeneration: 7, ConnectorID: "connector_1", ConnectorGeneration: 2, EdgePool: "development", EdgeNodeID: "edge_1", EdgeAssignmentHost: "edge.example.test", LeaseExpiresAt: time.Unix(2600, 0).UTC()})
	if err != nil {
		t.Fatal(err)
	}
	if descriptor.MachineGeneration != 7 || descriptor.ManagementURL != "https://machine.paperboat.invalid/v1/codex-sessions/cdx_1" || descriptor.WebSocketURL != "wss://machine.paperboat.invalid/v1/codex-sessions/cdx_1/ws" {
		t.Fatalf("descriptor=%+v", descriptor)
	}
}

func TestRequireCodexCapability(t *testing.T) {
	host := []string{"terminal_host", "codex_host"}
	for name, tc := range map[string]struct {
		online     bool
		configured []string
		observed   []string
		want       error
	}{
		"ready":                 {true, host, host, nil},
		"receive":               {true, []string{"file_receive", "preview_launch"}, []string{"file_receive", "preview_launch"}, ErrCapabilityUnavailable},
		"codex not configured":  {true, []string{"terminal_host"}, host, ErrCapabilityUnavailable},
		"offline":               {false, host, host, ErrMachineOffline},
		"terminal not observed": {true, host, []string{"codex_host"}, ErrMachineOffline},
		"codex not observed":    {true, host, []string{"terminal_host"}, ErrMachineOffline},
	} {
		t.Run(name, func(t *testing.T) {
			if got := requireCodexCapability(tc.online, tc.configured, tc.observed); !errors.Is(got, tc.want) || tc.want == nil && got != nil {
				t.Fatalf("requireCodexCapability()=%v, want %v", got, tc.want)
			}
		})
	}
}
