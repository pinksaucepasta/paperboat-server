package testdoctor

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestRunnerProducesStableSafeTypedChecks(t *testing.T) {
	root := testWorkspace(t)
	commands := make([]string, 0, 8)
	runner := Runner{Root: root, Timeout: time.Second, Command: func(_ context.Context, name string, args ...string) ([]byte, error) {
		commands = append(commands, name+" "+strings.Join(args, " "))
		switch name + " " + strings.Join(args, " ") {
		case "go env GOVERSION":
			return []byte("go1.26.6\n"), nil
		case "docker context show":
			return []byte("test\n"), nil
		case "docker context inspect --format {{.Endpoints.docker.Host}}":
			return []byte("tcp://docker.invalid:2376\n"), nil
		case "docker info --format {{.ServerVersion}}":
			return []byte("29.1.3\n"), nil
		case "docker image inspect " + requiredImages[0], "docker image inspect " + requiredImages[1]:
			return []byte("secret-image-metadata-that-must-not-be-emitted"), nil
		case "psql --version":
			return []byte("psql (PostgreSQL) 17.5\n"), nil
		default:
			return nil, errors.New("unexpected command")
		}
	}}
	report := runner.Run(context.Background())
	if report.Protocol != ProtocolVersion {
		t.Fatalf("report = %#v", report)
	}
	codes := make([]string, len(report.Checks))
	for index, check := range report.Checks {
		codes[index] = check.Code
		if check.Code == "" || check.Summary == "" || (check.Status != Pass && check.Recovery == "") {
			t.Fatalf("invalid check = %#v", check)
		}
	}
	want := []string{"disk_capacity", "docker_context", "docker_daemon", "docker_socket", "go_version", "loopback_ports", "memory_capacity", "network_admin", "postgres_tooling", "remote_testing", "required_files", "required_image_1", "required_image_2"}
	if !reflect.DeepEqual(codes, want) {
		t.Fatalf("codes = %#v", codes)
	}
	wire, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(wire), "secret-image-metadata") || strings.Contains(string(wire), "docker.invalid") {
		t.Fatalf("unsafe report = %s", wire)
	}
	for _, command := range commands {
		if strings.Contains(command, "pull") || strings.Contains(command, "run") || strings.Contains(command, "ssh") {
			t.Fatalf("mutating command executed: %s", command)
		}
	}
}

func TestRunnerFailsWrongGoWithoutEchoingCommandOutput(t *testing.T) {
	root := testWorkspace(t)
	report := (Runner{Root: root, Timeout: time.Second, Command: func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name == "go" {
			return []byte("go1.99.0 secret-token"), nil
		}
		return nil, errors.New("unavailable")
	}}).Run(context.Background())
	if report.Status != Fail {
		t.Fatalf("status = %s", report.Status)
	}
	wire, _ := json.Marshal(report)
	if strings.Contains(string(wire), "secret-token") {
		t.Fatalf("command output leaked: %s", wire)
	}
}

func TestEncodeUsesCanonicalFieldNames(t *testing.T) {
	wire, err := Encode(Report{Protocol: ProtocolVersion, Status: Warn, Checks: []Check{{Code: "network_admin", Status: Warn, Summary: "unavailable", Recovery: "grant capability"}}})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"protocol":"paperboat.test-doctor/v1","status":"warn","checks":[{"code":"network_admin","status":"warn","summary":"unavailable","recovery":"grant capability"}]}`
	if string(wire) != want {
		t.Fatalf("wire = %s", wire)
	}
}

func TestDockerUnavailableReturnsCompleteStableBoundary(t *testing.T) {
	checks, ready := checkDocker(context.Background(), func(context.Context, string, ...string) ([]byte, error) {
		return nil, errors.New("not found")
	}, time.Second)
	if ready {
		t.Fatal("docker unexpectedly ready")
	}
	want := []string{"docker_context", "docker_socket", "docker_daemon"}
	for index, code := range want {
		if checks[index].Code != code || checks[index].Status != Fail || checks[index].Recovery == "" {
			t.Fatalf("checks = %#v", checks)
		}
	}
}

func testWorkspace(t *testing.T) string {
	t.Helper()
	workspace := t.TempDir()
	root := filepath.Join(workspace, "paperboat-server")
	for _, path := range []string{
		filepath.Join(root, "go.mod"), filepath.Join(root, "Makefile"), filepath.Join(root, "tools", "run-control-storm.sh"),
		filepath.Join(workspace, "REMOTE_TESTING.md"), filepath.Join(workspace, "plans", "p2p-primary-transport.md"),
		filepath.Join(workspace, "paperboat", "go.mod"), filepath.Join(workspace, "paperboat-tunnel", "go.mod"),
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		content := []byte("test")
		if filepath.Base(path) == "REMOTE_TESTING.md" {
			content = []byte("Hetzner BatchMode=yes")
		}
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}
