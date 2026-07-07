package fly

import (
	"errors"
	"net/http"
	"os"
	"testing"

	flygo "github.com/superfly/fly-go"
	"github.com/superfly/fly-go/flaps"
)

func TestSDKMachineConfigUsesFlySDKShape(t *testing.T) {
	cfg := sdkMachineConfig(MachineSpec{
		Name: "pbvm-prj", ImageRef: "registry.example/app:test", Region: "iad",
		Size:     MachineSize{VCPU: 4, MemoryMB: 8192},
		VolumeID: "vol_1", MountPath: "/workspace",
		Env:        map[string]string{"PAPERBOAT_PROJECT_ID": "prj_1"},
		Secrets:    []MachineSecret{{EnvVar: "SECRET", Name: "secret-name", Value: "value"}},
		Command:    []string{"/entrypoint"},
		ConfigHash: "hash",
		Tags:       map[string]string{"paperboat_project_id": "prj_1", "managed_by": "paperboat-server"},
	})
	if cfg.Image != "registry.example/app:test" {
		t.Fatalf("image = %q", cfg.Image)
	}
	if cfg.Guest == nil || cfg.Guest.CPUKind != "shared" || cfg.Guest.CPUs != 4 || cfg.Guest.MemoryMB != 8192 {
		t.Fatalf("guest = %#v", cfg.Guest)
	}
	if cfg.Mounts[0].Volume != "vol_1" || cfg.Mounts[0].Path != "/workspace" {
		t.Fatalf("mounts = %#v", cfg.Mounts)
	}
	if cfg.Init.Cmd[0] != "/entrypoint" {
		t.Fatalf("init = %#v", cfg.Init)
	}
	if cfg.Metadata["paperboat_config_hash"] != "hash" || cfg.Metadata["paperboat_project_id"] != "prj_1" {
		t.Fatalf("metadata = %#v", cfg.Metadata)
	}
	if _, ok := cfg.Env["SECRET"]; ok {
		t.Fatalf("secret value leaked into env: %#v", cfg.Env)
	}
	if len(cfg.Processes) != 1 || !cfg.Processes[0].IgnoreAppSecrets {
		t.Fatalf("process secret isolation = %#v", cfg.Processes)
	}
	if len(cfg.Processes[0].Secrets) != 1 || cfg.Processes[0].Secrets[0].EnvVar != "SECRET" || cfg.Processes[0].Secrets[0].Name != "secret-name" {
		t.Fatalf("process secrets = %#v", cfg.Processes[0].Secrets)
	}
}

func TestSDKMachineConfigAlwaysIgnoresAppSecrets(t *testing.T) {
	cfg := sdkMachineConfig(MachineSpec{
		Name:     "pbvm-prj",
		ImageRef: "registry.example/app:test",
		Region:   "iad",
		Size:     MachineSize{VCPU: 1, MemoryMB: 256},
	})
	if len(cfg.Processes) != 1 || !cfg.Processes[0].IgnoreAppSecrets {
		t.Fatalf("process secret isolation = %#v", cfg.Processes)
	}
	if len(cfg.Processes[0].Secrets) != 0 {
		t.Fatalf("process secrets = %#v, want none", cfg.Processes[0].Secrets)
	}
}

func TestSDKMappingReadsMachineMetadata(t *testing.T) {
	machine := machineFromSDK(&flygo.Machine{
		ID:     "mach_1",
		Name:   "pbvm-prj",
		State:  "stopped",
		Region: "iad",
		Config: &flygo.MachineConfig{
			Image: "registry.example/app:test",
			Metadata: map[string]string{
				"paperboat_project_id":  "prj_1",
				"managed_by":            "paperboat-server",
				"paperboat_config_hash": "hash",
			},
		},
	})
	if machine.ID != "mach_1" || machine.ImageRef != "registry.example/app:test" || machine.ConfigHash != "hash" {
		t.Fatalf("machine = %#v", machine)
	}
	if machine.Tags["managed_by"] != "paperboat-server" {
		t.Fatalf("tags = %#v", machine.Tags)
	}
}

func TestSDKErrorMapsNotFound(t *testing.T) {
	err := &flaps.FlapsError{ResponseStatusCode: http.StatusNotFound}
	if !errors.Is(mapSDKError(err), ErrNotFound) {
		t.Fatalf("error = %v, want ErrNotFound", mapSDKError(err))
	}
}

func TestWithFlapsBaseURLOverridesAndRestoresEnv(t *testing.T) {
	const key = "FLY_FLAPS_BASE_URL"
	previous, hadPrevious := os.LookupEnv(key)
	t.Cleanup(func() {
		if hadPrevious {
			_ = os.Setenv(key, previous)
			return
		}
		_ = os.Unsetenv(key)
	})
	if err := os.Setenv(key, "https://old.example.test"); err != nil {
		t.Fatal(err)
	}
	restore, err := withFlapsBaseURL(" https://fly.example.test ")
	if err != nil {
		t.Fatal(err)
	}
	if got := os.Getenv(key); got != "https://fly.example.test" {
		t.Fatalf("%s = %q", key, got)
	}
	restore()
	if got := os.Getenv(key); got != "https://old.example.test" {
		t.Fatalf("restored %s = %q", key, got)
	}
}

func TestWithFlapsBaseURLLeavesEnvUnsetWhenBlank(t *testing.T) {
	const key = "FLY_FLAPS_BASE_URL"
	previous, hadPrevious := os.LookupEnv(key)
	t.Cleanup(func() {
		if hadPrevious {
			_ = os.Setenv(key, previous)
			return
		}
		_ = os.Unsetenv(key)
	})
	_ = os.Unsetenv(key)
	restore, err := withFlapsBaseURL("")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := os.LookupEnv(key); ok {
		t.Fatalf("%s should remain unset", key)
	}
	restore()
	if _, ok := os.LookupEnv(key); ok {
		t.Fatalf("%s should remain unset after restore", key)
	}
}
