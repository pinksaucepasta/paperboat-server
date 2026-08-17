package testdoctor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	ProtocolVersion = "paperboat.test-doctor/v1"
	requiredGo      = "go1.26.6"
	minimumDisk     = uint64(10 << 30)
	minimumMemory   = uint64(4 << 30)
)

var requiredImages = []string{
	"golang:1.26.6-bookworm@sha256:116d58cbd88c1297624acc6e967a060012422bacf9930927e23fb719189c6f36",
	"postgres:17.5-bookworm@sha256:fbcea1bd13b6a882cd6caa6b58db3ae5c102efe50ec625b3e2a5cbc50db5bfe4",
}

type Status string

const (
	Pass Status = "pass"
	Warn Status = "warn"
	Fail Status = "fail"
)

type Check struct {
	Code     string `json:"code"`
	Status   Status `json:"status"`
	Summary  string `json:"summary"`
	Recovery string `json:"recovery,omitempty"`
}

type Report struct {
	Protocol string  `json:"protocol"`
	Status   Status  `json:"status"`
	Checks   []Check `json:"checks"`
}

type commandRunner func(context.Context, string, ...string) ([]byte, error)

type Runner struct {
	Root    string
	Command commandRunner
	Timeout time.Duration
}

func (r Runner) Run(ctx context.Context) Report {
	root := filepath.Clean(r.Root)
	if root == "." || root == "" {
		if current, err := os.Getwd(); err == nil {
			root = current
		}
	}
	timeout := r.Timeout
	if timeout <= 0 || timeout > 30*time.Second {
		timeout = 5 * time.Second
	}
	command := r.Command
	if command == nil {
		command = runCommand
	}
	checks := []Check{
		checkGo(ctx, command, timeout),
		checkRequiredFiles(root),
		checkDisk(root),
		checkMemory(ctx, command, timeout),
		checkLoopback(),
		checkNetworkAdmin(),
		checkRemoteConfiguration(root),
	}
	dockerChecks, dockerReady := checkDocker(ctx, command, timeout)
	checks = append(checks, dockerChecks...)
	checks = append(checks, checkImages(ctx, command, timeout, dockerReady)...)
	checks = append(checks, checkPostgresTooling(ctx, command, timeout, dockerReady))
	sort.Slice(checks, func(i, j int) bool { return checks[i].Code < checks[j].Code })
	return Report{Protocol: ProtocolVersion, Status: aggregate(checks), Checks: checks}
}

func checkGo(ctx context.Context, command commandRunner, timeout time.Duration) Check {
	output, err := boundedCommand(ctx, command, timeout, "go", "env", "GOVERSION")
	version := strings.TrimSpace(string(output))
	if err != nil {
		return failed("go_version", "Go is unavailable", "Install Go 1.26.6 and ensure go is on PATH.")
	}
	if version != requiredGo {
		return failed("go_version", "Go version does not match the pinned toolchain", "Install and select Go 1.26.6; then rerun paperboat-test doctor.")
	}
	return passed("go_version", "Go 1.26.6 is selected")
}

func checkRequiredFiles(root string) Check {
	paths := []string{"go.mod", "Makefile", "tools/run-control-storm.sh", "../REMOTE_TESTING.md", "../plans/p2p-primary-transport.md", "../paperboat/go.mod", "../paperboat-tunnel/go.mod"}
	for _, path := range paths {
		info, err := os.Stat(filepath.Join(root, path))
		if err != nil || !info.Mode().IsRegular() {
			return failed("required_files", "The Paperboat workspace is incomplete", "Run paperboat-test from the paperboat-server repository inside the complete Paperboat workspace.")
		}
	}
	return passed("required_files", "Required workspace files are present")
}

func checkDisk(root string) Check {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(root, &stat); err != nil {
		return warned("disk_capacity", "Available disk space could not be measured", "Ensure at least 10 GiB is free before running component tests.")
	}
	available := uint64(stat.Bavail) * uint64(stat.Bsize)
	if available < minimumDisk {
		return failed("disk_capacity", "Less than 10 GiB of disk space is available", "Free at least 10 GiB on the workspace filesystem.")
	}
	return passed("disk_capacity", "At least 10 GiB of disk space is available")
}

func checkMemory(ctx context.Context, command commandRunner, timeout time.Duration) Check {
	var bytes uint64
	if runtime.GOOS == "linux" {
		data, err := os.ReadFile("/proc/meminfo")
		if err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				fields := strings.Fields(line)
				if len(fields) >= 2 && fields[0] == "MemTotal:" {
					value, parseErr := strconv.ParseUint(fields[1], 10, 64)
					if parseErr == nil {
						bytes = value << 10
					}
				}
			}
		}
	} else if runtime.GOOS == "darwin" {
		output, err := boundedCommand(ctx, command, timeout, "sysctl", "-n", "hw.memsize")
		if err == nil {
			bytes, _ = strconv.ParseUint(strings.TrimSpace(string(output)), 10, 64)
		}
	}
	if bytes == 0 {
		return warned("memory_capacity", "System memory could not be measured", "Ensure at least 4 GiB of memory is available before running component tests.")
	}
	if bytes < minimumMemory {
		return failed("memory_capacity", "The system has less than 4 GiB of memory", "Use a test host with at least 4 GiB of memory.")
	}
	return passed("memory_capacity", "The system has at least 4 GiB of memory")
}

func checkLoopback() Check {
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return failed("loopback_ports", "A loopback TCP port cannot be allocated", "Restore loopback networking and allow local ephemeral TCP listeners.")
	}
	_ = tcp.Close()
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return failed("loopback_ports", "A loopback UDP port cannot be allocated", "Restore loopback networking and allow local ephemeral UDP sockets.")
	}
	_ = udp.Close()
	return passed("loopback_ports", "Loopback TCP and UDP ports are available")
}

func checkNetworkAdmin() Check {
	if runtime.GOOS != "linux" {
		return warned("network_admin", "Network-administration capability is not directly observable on this host", "Run fault-injection tests in the repository harness, which requests network-administration capability explicitly.")
	}
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return warned("network_admin", "Network-administration capability could not be read", "Grant CAP_NET_ADMIN to the component-test runner when latency, loss, or UDP-block tests are required.")
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || fields[0] != "CapEff:" {
			continue
		}
		value, parseErr := strconv.ParseUint(fields[1], 16, 64)
		if parseErr == nil && value&(1<<12) != 0 {
			return passed("network_admin", "CAP_NET_ADMIN is available")
		}
		return warned("network_admin", "CAP_NET_ADMIN is unavailable to this process", "Grant CAP_NET_ADMIN to the component-test runner for latency, loss, and UDP-block scenarios.")
	}
	return warned("network_admin", "Network-administration capability could not be determined", "Grant CAP_NET_ADMIN to the component-test runner when fault injection is required.")
}

func checkRemoteConfiguration(root string) Check {
	path := filepath.Join(root, "..", "REMOTE_TESTING.md")
	data, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(data), "BatchMode=yes") || !strings.Contains(string(data), "Hetzner") {
		return warned("remote_testing", "Remote-test configuration is unavailable", "Configure the authorized targets in workspace REMOTE_TESTING.md without placing private key contents in the workspace.")
	}
	return passed("remote_testing", "Remote-test instructions are configured")
}

func checkDocker(ctx context.Context, command commandRunner, timeout time.Duration) ([]Check, bool) {
	contextOutput, contextErr := boundedCommand(ctx, command, timeout, "docker", "context", "show")
	if contextErr != nil || strings.TrimSpace(string(contextOutput)) == "" {
		return []Check{
			failed("docker_context", "The Docker context is unavailable", "Install Docker, then select a valid context with docker context use."),
			failed("docker_socket", "The Docker endpoint was not checked", "Install Docker and configure an isolated local or remote endpoint."),
			failed("docker_daemon", "The Docker daemon was not checked", "Install and start Docker after selecting a valid context."),
		}, false
	}
	checks := []Check{passed("docker_context", "A Docker context is selected")}
	hostOutput, hostErr := boundedCommand(ctx, command, timeout, "docker", "context", "inspect", "--format", "{{.Endpoints.docker.Host}}")
	if hostErr != nil || strings.TrimSpace(string(hostOutput)) == "" {
		checks = append(checks, failed("docker_socket", "The Docker endpoint is unavailable", "Repair the selected Docker context endpoint."))
	} else {
		host := strings.TrimSpace(string(hostOutput))
		if strings.HasPrefix(host, "unix://") {
			info, err := os.Stat(strings.TrimPrefix(host, "unix://"))
			if err != nil || info.Mode()&os.ModeSocket == 0 {
				checks = append(checks, failed("docker_socket", "The Docker Unix socket is unavailable", "Start Docker or repair the selected context socket path."))
			} else {
				checks = append(checks, passed("docker_socket", "The Docker Unix socket is available"))
			}
		} else {
			checks = append(checks, warned("docker_socket", "The Docker context uses a non-Unix endpoint", "Confirm the remote or desktop Docker endpoint is intentional and isolated for component tests."))
		}
	}
	if _, err := boundedCommand(ctx, command, timeout, "docker", "info", "--format", "{{.ServerVersion}}"); err != nil {
		checks = append(checks, failed("docker_daemon", "The Docker daemon is unavailable", "Start the Docker daemon and verify docker info succeeds."))
		return checks, false
	}
	checks = append(checks, passed("docker_daemon", "The Docker daemon is reachable"))
	return checks, true
}

func checkImages(ctx context.Context, command commandRunner, timeout time.Duration, dockerReady bool) []Check {
	checks := make([]Check, 0, len(requiredImages))
	for index, image := range requiredImages {
		code := fmt.Sprintf("required_image_%d", index+1)
		if !dockerReady {
			checks = append(checks, warned(code, "A required pinned image was not checked", "Start Docker, then run docker pull "+image+"."))
			continue
		}
		if _, err := boundedCommand(ctx, command, timeout, "docker", "image", "inspect", image); err != nil {
			checks = append(checks, warned(code, "A required pinned image is not present locally", "Run docker pull "+image+"."))
		} else {
			checks = append(checks, passed(code, "A required pinned image is present"))
		}
	}
	return checks
}

func checkPostgresTooling(ctx context.Context, command commandRunner, timeout time.Duration, dockerReady bool) Check {
	if _, err := boundedCommand(ctx, command, timeout, "psql", "--version"); err == nil {
		return passed("postgres_tooling", "PostgreSQL client tooling is available")
	}
	if dockerReady {
		if _, err := boundedCommand(ctx, command, timeout, "docker", "image", "inspect", requiredImages[1]); err == nil {
			return passed("postgres_tooling", "Pinned PostgreSQL container tooling is available")
		}
	}
	return warned("postgres_tooling", "PostgreSQL tooling is unavailable", "Install psql or run docker pull "+requiredImages[1]+".")
}

func boundedCommand(ctx context.Context, command commandRunner, timeout time.Duration, name string, args ...string) ([]byte, error) {
	commandCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	output, err := command(commandCtx, name, args...)
	if len(output) > 64<<10 {
		return nil, errors.New("command output exceeds limit")
	}
	return output, err
}

func runCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

func aggregate(checks []Check) Status {
	status := Pass
	for _, check := range checks {
		if check.Status == Fail {
			return Fail
		}
		if check.Status == Warn {
			status = Warn
		}
	}
	return status
}

func passed(code, summary string) Check { return Check{Code: code, Status: Pass, Summary: summary} }
func warned(code, summary, recovery string) Check {
	return Check{Code: code, Status: Warn, Summary: summary, Recovery: recovery}
}
func failed(code, summary, recovery string) Check {
	return Check{Code: code, Status: Fail, Summary: summary, Recovery: recovery}
}

func Encode(report Report) ([]byte, error) { return json.Marshal(report) }
