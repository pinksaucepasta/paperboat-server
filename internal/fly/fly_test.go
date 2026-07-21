package fly

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	flygo "github.com/superfly/fly-go"
	"github.com/superfly/fly-go/flaps"
)

func TestSDKMachineConfigUsesFlySDKShape(t *testing.T) {
	cfg := sdkMachineConfig(MachineSpec{
		Name: "pbvm-prj", ImageRef: "registry.example/app:test", Region: "iad",
		Size:     MachineSize{VCPU: 4, MemoryMB: 8192},
		VolumeID: "vol_1", MountPath: "/workspace",
		Env:         map[string]string{"PAPERBOAT_PROJECT_ID": "prj_1"},
		Secrets:     []MachineSecret{{EnvVar: "SECRET", Name: "secret-name", Value: "value"}},
		Command:     []string{"/entrypoint"},
		StopTimeout: 42 * time.Second,
		ConfigHash:  "hash",
		Tags:        map[string]string{"paperboat_project_id": "prj_1", "managed_by": "paperboat-server"},
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
	if cfg.StopConfig == nil || cfg.StopConfig.Timeout == nil || cfg.StopConfig.Timeout.Duration != 42*time.Second || cfg.StopConfig.Signal == nil || *cfg.StopConfig.Signal != "SIGTERM" {
		t.Fatalf("stop config = %#v", cfg.StopConfig)
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
	if len(cfg.Services) != 0 {
		t.Fatalf("project machine exposes public Fly services: %#v", cfg.Services)
	}
}

func TestSDKMachineConfigSetsHostname(t *testing.T) {
	cfg := sdkMachineConfig(MachineSpec{
		Name:     "pbvm-prj",
		Hostname: "paperboat",
		ImageRef: "registry.example/app:test",
		Region:   "iad",
		Size:     MachineSize{VCPU: 1, MemoryMB: 256},
	})
	if cfg.DNS == nil || cfg.DNS.Hostname != "paperboat" {
		t.Fatalf("dns = %#v", cfg.DNS)
	}

	// No hostname means no DNS override is written.
	bare := sdkMachineConfig(MachineSpec{Name: "pbvm-prj", ImageRef: "img", Region: "iad", Size: MachineSize{VCPU: 1, MemoryMB: 256}})
	if bare.DNS != nil {
		t.Fatalf("expected nil dns, got %#v", bare.DNS)
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

func TestSDKMachineConfigRetainsSecretReferenceWithoutRewritingValue(t *testing.T) {
	cfg := sdkMachineConfig(MachineSpec{Secrets: []MachineSecret{{EnvVar: "ENROLLMENT", Name: "PBSECRET_ENROLLMENT", Value: ""}}})
	if len(cfg.Processes) != 1 || len(cfg.Processes[0].Secrets) != 1 || cfg.Processes[0].Secrets[0].EnvVar != "ENROLLMENT" || cfg.Processes[0].Secrets[0].Name != "PBSECRET_ENROLLMENT" {
		t.Fatalf("secret references = %#v", cfg.Processes)
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
	mapped := mapSDKError(err)
	if !errors.Is(mapped, ErrNotFound) {
		t.Fatalf("error = %v, want ErrNotFound", mapSDKError(err))
	}
	var providerErr *ProviderError
	if !errors.As(mapped, &providerErr) || providerErr.Outcome != OutcomeNotFound {
		t.Fatalf("mapped = %#v, want not_found provider error", mapped)
	}
}

func TestSDKMapsNilProviderObjectsToNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/apps/paperboat-test/volumes/vol_missing" && r.URL.Path != "/v1/apps/paperboat-test/machines/mach_missing" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("null"))
	}))
	defer server.Close()

	client := &SDKClient{AppName: "paperboat-test", BaseURL: server.URL}
	if _, err := client.GetVolume(context.Background(), "vol_missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("volume error = %v, want ErrNotFound", err)
	}
	if _, err := client.GetMachine(context.Background(), "mach_missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("machine error = %v, want ErrNotFound", err)
	}
}

func TestSDKErrorClassifiesProviderOutcomes(t *testing.T) {
	for _, tc := range []struct {
		status int
		want   Outcome
	}{
		{http.StatusTooManyRequests, OutcomeRetryable},
		{http.StatusServiceUnavailable, OutcomeRetryable},
		{http.StatusConflict, OutcomeConflict},
		{http.StatusBadRequest, OutcomePermanent},
	} {
		mapped := mapSDKError(&flaps.FlapsError{ResponseStatusCode: tc.status})
		var providerErr *ProviderError
		if !errors.As(mapped, &providerErr) || providerErr.Outcome != tc.want {
			t.Errorf("status %d mapped to %#v, want %s", tc.status, mapped, tc.want)
		}
	}
}

func TestSDKErrorClassifiesRegionalCapacity(t *testing.T) {
	mapped := mapSDKError(&flaps.FlapsError{
		ResponseStatusCode: http.StatusBadRequest,
		ResponseBody:       []byte(`{"error":"no capacity","status":"insufficient_capacity"}`),
	})
	var providerErr *ProviderError
	if !errors.As(mapped, &providerErr) || providerErr.Outcome != OutcomeCapacity {
		t.Fatalf("mapped = %#v, want capacity error", mapped)
	}
}

func TestMutationErrorMakesRetryableOutcomeUncertain(t *testing.T) {
	mapped := mapMutationError("create_machine", &flaps.FlapsError{ResponseStatusCode: http.StatusServiceUnavailable})
	var providerErr *ProviderError
	if !errors.As(mapped, &providerErr) || providerErr.Outcome != OutcomeUncertain || providerErr.Operation != "create_machine" {
		t.Fatalf("mapped = %#v, want uncertain create_machine error", mapped)
	}

	mapped = mapMutationError("create_machine", &flaps.FlapsError{ResponseStatusCode: http.StatusConflict})
	if !errors.As(mapped, &providerErr) || providerErr.Outcome != OutcomeConflict {
		t.Fatalf("mapped = %#v, want conflict error", mapped)
	}
}

func TestMutationErrorTreatsMachineReplacementConflictAsUncertain(t *testing.T) {
	mapped := mapMutationError("start_machine", &flaps.FlapsError{
		ResponseStatusCode: http.StatusConflict,
		ResponseBody:       []byte(`{"error":"failed_precondition: machine getting replaced, refusing to start"}`),
	})
	var providerErr *ProviderError
	if !errors.As(mapped, &providerErr) || providerErr.Outcome != OutcomeUncertain || providerErr.Operation != "start_machine" {
		t.Fatalf("mapped = %#v, want uncertain start_machine error", mapped)
	}
}

func TestMutationErrorMakesTransportFailureUncertain(t *testing.T) {
	mapped := mapMutationError("delete_secret", context.DeadlineExceeded)
	var providerErr *ProviderError
	if !errors.As(mapped, &providerErr) || providerErr.Outcome != OutcomeUncertain || providerErr.Operation != "delete_secret" || !errors.Is(mapped, context.DeadlineExceeded) {
		t.Fatalf("mapped = %#v, want uncertain delete_secret deadline", mapped)
	}
}

func TestSDKMutationPreservesProviderRequestID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete || r.URL.Path != "/v1/apps/paperboat-test/secrets/PBSECRET_TEST" {
			t.Fatalf("request = %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("fly-request-id", "fly-request-123")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":"provider unavailable"}`))
	}))
	defer server.Close()

	err := (&SDKClient{AppName: "paperboat-test", BaseURL: server.URL}).DeleteSecret(context.Background(), "PBSECRET_TEST")
	var providerErr *ProviderError
	if !errors.As(err, &providerErr) || providerErr.Outcome != OutcomeUncertain || providerErr.Operation != "delete_secret" || providerErr.RequestID != "fly-request-123" {
		t.Fatalf("error = %#v, want uncertain delete_secret with request ID", err)
	}
}

func TestSDKMutationCancellationIsUncertain(t *testing.T) {
	requestStarted := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(requestStarted)
		<-r.Context().Done()
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- (&SDKClient{AppName: "paperboat-test", BaseURL: server.URL}).DeleteSecret(ctx, "PBSECRET_TEST")
	}()
	<-requestStarted
	cancel()
	err := <-done
	var providerErr *ProviderError
	if !errors.As(err, &providerErr) || providerErr.Outcome != OutcomeUncertain || providerErr.Operation != "delete_secret" || !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %#v, want uncertain canceled delete_secret", err)
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
