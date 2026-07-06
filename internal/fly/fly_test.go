package fly

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHTTPClientCreateMachineUsesFlyRequestShape(t *testing.T) {
	var payload map[string]any
	secretValues := map[string]string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/secrets/") {
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			secretValues[strings.TrimPrefix(r.URL.Path, "/v1/apps/app/secrets/")] = body["value"]
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.URL.Path != "/v1/apps/app/machines" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"mach_1","name":"pbvm-prj","state":"stopped","region":"iad","config":{"image":"registry.example/app:test","metadata":{"paperboat_project_id":"prj_1","managed_by":"paperboat-server","paperboat_config_hash":"hash"}}}`))
	}))
	defer server.Close()

	client := HTTPClient{BaseURL: server.URL, APIToken: "token", AppName: "app"}
	machine, err := client.CreateMachine(context.Background(), MachineSpec{
		Name: "pbvm-prj", ImageRef: "registry.example/app:test", Region: "iad",
		Size:     MachineSize{VCPU: 4, MemoryMB: 8192},
		VolumeID: "vol_1", MountPath: "/workspace",
		Env:        map[string]string{"PAPERBOAT_PROJECT_ID": "prj_1"},
		Secrets:    []MachineSecret{{EnvVar: "SECRET", Name: "secret-name", Value: "value"}},
		Command:    []string{"/entrypoint"},
		ConfigHash: "hash",
		Tags:       map[string]string{"paperboat_project_id": "prj_1", "managed_by": "paperboat-server"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if machine.ID != "mach_1" || machine.Tags["paperboat_project_id"] != "prj_1" {
		t.Fatalf("machine response = %#v", machine)
	}
	if _, ok := payload["Name"]; ok {
		t.Fatalf("payload used Go field names: %#v", payload)
	}
	if payload["name"] != "pbvm-prj" || payload["region"] != "iad" {
		t.Fatalf("top-level payload = %#v", payload)
	}
	config, ok := payload["config"].(map[string]any)
	if !ok {
		t.Fatalf("payload missing config object: %#v", payload)
	}
	if config["image"] != "registry.example/app:test" {
		t.Fatalf("config.image = %#v", config["image"])
	}
	if _, ok := config["VolumeID"]; ok {
		t.Fatalf("config used Go field names: %#v", config)
	}
	mounts := config["mounts"].([]any)
	if mounts[0].(map[string]any)["volume"] != "vol_1" {
		t.Fatalf("mounts = %#v", mounts)
	}
	secrets := config["secrets"].([]any)
	if secrets[0].(map[string]any)["env_var"] != "SECRET" || secrets[0].(map[string]any)["name"] != "secret-name" {
		t.Fatalf("config.secrets = %#v", secrets)
	}
	env := config["env"].(map[string]any)
	if env["SECRET"] != nil {
		t.Fatalf("env leaked secret value: %#v", env)
	}
	if secretValues["secret-name"] != "value" {
		t.Fatalf("secret endpoint values = %#v", secretValues)
	}
}

func TestHTTPClientMapsNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer server.Close()

	client := HTTPClient{BaseURL: server.URL, APIToken: "token", AppName: "app"}
	if _, err := client.GetMachine(context.Background(), "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetMachine error = %v, want ErrNotFound", err)
	}
	if err := client.DestroyVolume(context.Background(), "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("DestroyVolume error = %v, want ErrNotFound", err)
	}
}

func TestHTTPClientListVolumes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/volumes") {
			t.Fatalf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"id":"vol_1","name":"pbvol-prj","size_gb":8,"region":"iad","state":"created"}]`))
	}))
	defer server.Close()

	client := HTTPClient{BaseURL: server.URL, APIToken: "token", AppName: "app"}
	volumes, err := client.ListVolumes(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(volumes) != 1 || volumes[0].ID != "vol_1" || volumes[0].SizeGB != 8 {
		t.Fatalf("volumes = %#v", volumes)
	}
}
