package codexsessions

import (
	"errors"
	"testing"
)

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
