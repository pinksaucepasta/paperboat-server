//go:build topology

package testtopology

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ory/dockertest/v3"
	docker "github.com/ory/dockertest/v3/docker"
)

const topologyGoImage = "golang:1.27.1-bookworm@sha256:648f440f42a0958804efb24df176f806f9d353b41f1c0627f666428e40310f6b"

const topologyNetToolsImage = "nicolaka/netshoot@sha256:a20c2531bf35436ed3766cd6cfe89d352b050ccc4d7005ce6400adf97503da1b"

const topologyPostgresImage = "postgres:17.5-bookworm@sha256:fbcea1bd13b6a882cd6caa6b58db3ae5c102efe50ec625b3e2a5cbc50db5bfe4"

var topologyRsyncPackages = []struct {
	name   string
	sha256 string
}{
	{"rsync-3.4.1-r1.apk", "4cece413774c3d9a95fbe9c6c9d7250cb44dfac513908991456cbc213df147b3"},
	{"libacl-2.3.1-r4.apk", "75502f59c013a3f1a6471f8e8e05d6c393fdb7d5fb2a29ad580fd9b03ccb8a55"},
	{"libxxhash-0.8.2-r2.apk", "0276bcf4b8a054655593b5cb748e96498352ddc85618ddd08ad93fbc2e44a145"},
}

const topologyAlpinePackageBaseURL = "https://dl-cdn.alpinelinux.org/alpine/v3.19/main/x86_64/"

func TestSplitDigestImageRequiresExactSHA256(t *testing.T) {
	repository, tag, err := splitDigestImage(topologyGoImage)
	if err != nil || repository != "golang:1.27.1-bookworm@sha256" || len(tag) != 64 {
		t.Fatalf("split = %q %q %v", repository, tag, err)
	}
	repository, tag, err = splitDigestImage(topologyNetToolsImage)
	if err != nil || repository != "nicolaka/netshoot@sha256" || len(tag) != 64 {
		t.Fatalf("network tools split = %q %q %v", repository, tag, err)
	}
	for _, invalid := range []string{"", "golang:latest", "golang@sha256:short", topologyGoImage + " extra", "@sha256:" + strings.Repeat("a", 64)} {
		if _, _, err := splitDigestImage(invalid); !errors.Is(err, ErrInvalid) {
			t.Fatalf("image %q accepted", invalid)
		}
	}
}

func TestRunIDsAndRolesAreBounded(t *testing.T) {
	first, err := newRunID("paperboat")
	if err != nil {
		t.Fatal(err)
	}
	second, err := newRunID("paperboat")
	if err != nil {
		t.Fatal(err)
	}
	if first == second || len(first) != len("paperboat-")+20 || !strings.HasPrefix(first, "paperboat-") {
		t.Fatalf("run IDs = %q %q", first, second)
	}
	for _, role := range []string{"client", "host-1", "postgres"} {
		if !validRole(role) {
			t.Fatalf("valid role %q rejected", role)
		}
	}
	for _, role := range []string{"", "UPPER", "-bad", strings.Repeat("a", 49), "bad_role"} {
		if validRole(role) {
			t.Fatalf("invalid role %q accepted", role)
		}
	}
}

func TestClearingInactiveNetworkImpairmentIsNoop(t *testing.T) {
	scope := &Scope{
		containers: map[string]*dockertest.Resource{"client": {}},
		faults:     make(map[string]faultState),
		mu:         sync.Mutex{},
	}
	if err := scope.SetNetworkImpairment("client", 0, 0); err != nil {
		t.Fatal(err)
	}
	if len(scope.Evidence().Events) != 0 {
		t.Fatal("no-op impairment clear recorded an event")
	}
}

func TestBoundedLogsAndResourceValidators(t *testing.T) {
	buffer := newBoundedBuffer(4)
	if written, err := buffer.Write([]byte("abcdef")); err != nil || written != 6 || string(buffer.Bytes()) != "abcd" || !buffer.truncated {
		t.Fatalf("bounded write = %d %q %t %v", written, buffer.Bytes(), buffer.truncated, err)
	}
	for _, port := range []string{"1/tcp", "443/udp", "65535/tcp"} {
		if !validPort(port) {
			t.Fatalf("valid port %q rejected", port)
		}
	}
	for _, port := range []string{"0/tcp", "65536/tcp", "80", "80/sctp", " 80/tcp"} {
		if validPort(port) {
			t.Fatalf("invalid port %q accepted", port)
		}
	}
	for _, path := range []string{"/data", "/var/lib/paperboat"} {
		if !validContainerPath(path) {
			t.Fatalf("valid path %q rejected", path)
		}
	}
	for _, path := range []string{"", "/", "relative", "/data:ro", "/data/../secret"} {
		if validContainerPath(path) {
			t.Fatalf("invalid path %q accepted", path)
		}
	}
}

func TestConcurrentScopesOwnAndCleanOnlyTheirResources(t *testing.T) {
	if os.Getenv("PAPERBOAT_TOPOLOGY_TEST") != "1" {
		t.Skip("set PAPERBOAT_TOPOLOGY_TEST=1 to run Docker topology isolation")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	first := newIntegrationScope(t, ctx, "pbtopology-a")
	second := newIntegrationScope(t, ctx, "pbtopology-b")
	firstClosed, secondClosed := false, false
	t.Cleanup(func() {
		if !firstClosed {
			_, _ = first.Close(true)
		}
		if !secondClosed {
			_, _ = second.Close(true)
		}
	})

	for _, scope := range []*Scope{first, second} {
		if err := scope.CreateNetwork(ctx, "client", true); err != nil {
			t.Fatal(err)
		}
		if err := scope.CreateNetwork(ctx, "control", false); err != nil {
			t.Fatal(err)
		}
		if err := scope.CreateVolume(ctx, "state"); err != nil {
			t.Fatal(err)
		}
		if err := scope.RunContainer(ctx, ContainerSpec{
			Role: "client", Image: topologyGoImage, Command: []string{"sh", "-c", "printf '%s' \"$PAPERBOAT_MARKER\" > /state/marker; echo topology-ready; echo topology-diagnostic >&2; while :; do sleep 60; done"},
			Environment: []string{"PAPERBOAT_MARKER=" + scope.RunID()}, Networks: []string{"client", "control"},
			Volumes: []VolumeMount{{Role: "state", ContainerPath: "/state"}}, PublishPorts: []string{"8080/tcp"},
			MemoryBytes: 64 << 20, CPUQuota: 25000, PIDs: 32,
		}); err != nil {
			t.Fatal(err)
		}
		hostPort, err := scope.HostPort("client", "8080/tcp")
		if err != nil || !strings.HasPrefix(hostPort, "127.0.0.1:") {
			t.Fatalf("host port = %q %v", hostPort, err)
		}
		var logs ContainerLogs
		deadline := time.Now().Add(5 * time.Second)
		for {
			logs, err = scope.Logs(ctx, "client", 1024)
			if err == nil && strings.Contains(string(logs.Stdout), "topology-ready") && strings.Contains(string(logs.Stderr), "topology-diagnostic") && !logs.Truncated {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("logs = %#v %v", logs, err)
			}
			time.Sleep(50 * time.Millisecond)
		}
		sample, err := scope.Sample(ctx, "client")
		if err != nil || sample.Role != "client" || sample.PIDs == 0 {
			t.Fatalf("sample = %#v %v", sample, err)
		}
	}
	if first.RunID() == second.RunID() {
		t.Fatal("concurrent scopes share a run ID")
	}
	if err := first.Disconnect(ctx, "client", "control"); err != nil {
		t.Fatal(err)
	}
	if err := first.Reconnect(ctx, "client", "control"); err != nil {
		t.Fatal(err)
	}
	if err := first.Restart(ctx, "client", time.Second); err != nil {
		t.Fatal(err)
	}
	firstReport, err := first.Close(true)
	if err != nil {
		t.Fatal(err)
	}
	firstClosed = true
	if firstReport.RemovedContainers != 1 || firstReport.RemovedNetworks != 2 || firstReport.RemovedVolumes != 1 {
		t.Fatalf("first cleanup = %#v", firstReport)
	}
	if err := second.Restart(ctx, "client", time.Second); err != nil {
		t.Fatalf("first cleanup touched second run: %v", err)
	}
	resource := second.containers["client"]
	if code, err := resource.Exec([]string{"sh", "-c", "test \"$(cat /state/marker)\" = \"$PAPERBOAT_MARKER\""}, dockertest.ExecOptions{}); err != nil || code != 0 {
		t.Fatalf("first cleanup touched second volume: exit=%d %v", code, err)
	}
	if _, err := second.HostPort("client", "8080/tcp"); err != nil {
		t.Fatalf("first cleanup touched second port binding: %v", err)
	}
	secondReport, err := second.Close(true)
	if err != nil {
		t.Fatal(err)
	}
	secondClosed = true
	if secondReport.RemovedContainers != 1 || secondReport.RemovedNetworks != 2 || secondReport.RemovedVolumes != 1 {
		t.Fatalf("second cleanup = %#v", secondReport)
	}
	for _, runID := range []string{first.RunID(), second.RunID()} {
		containers, err := second.pool.Client.ListContainers(dockerListByRun(runID))
		if err != nil || len(containers) != 0 {
			t.Fatalf("containers retained for %s: %d %v", runID, len(containers), err)
		}
		for _, network := range mustNetworks(t, second) {
			if network.Labels[RunLabel] == runID {
				t.Fatalf("network %s retained for %s", network.Name, runID)
			}
		}
	}
	if len(first.Evidence().Events) < 8 || len(second.Evidence().Events) < 6 {
		t.Fatal("bounded lifecycle evidence is incomplete")
	}
}

func TestRegionalRelaySelectionAuthorityAcrossPostgres(t *testing.T) {
	if os.Getenv("PAPERBOAT_TOPOLOGY_TEST") != "1" {
		t.Skip("set PAPERBOAT_TOPOLOGY_TEST=1 to run Docker topology isolation")
	}
	authorityBinary := os.Getenv("PAPERBOAT_TOPOLOGY_REGIONAL_AUTHORITY_BINARY")
	if authorityBinary == "" {
		t.Fatal("PAPERBOAT_TOPOLOGY_REGIONAL_AUTHORITY_BINARY is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	scope := newIntegrationScope(t, ctx, "pbregion")
	closed := false
	t.Cleanup(func() {
		if !closed {
			_, _ = scope.Close(true)
		}
	})
	if err := scope.CreateNetwork(ctx, "database", false); err != nil {
		t.Fatal(err)
	}
	if err := scope.RunContainer(ctx, ContainerSpec{Role: "postgres", Image: topologyPostgresImage, Command: []string{"postgres"}, Environment: []string{"POSTGRES_USER=paperboat", "POSTGRES_PASSWORD=paperboat-test-only", "POSTGRES_DB=paperboat_test"}, Networks: []string{"database"}, MemoryBytes: 384 << 20, CPUQuota: 50000, PIDs: 128}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(45 * time.Second)
	postgresReady := false
	for time.Now().Before(deadline) {
		if err := scope.Exec(ctx, "postgres", []string{"pg_isready", "-U", "paperboat", "-d", "paperboat_test"}); err == nil {
			postgresReady = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !postgresReady {
		t.Fatal("postgres did not become ready")
	}
	postgresAddress, err := scope.ContainerAddress("postgres", "database")
	if err != nil {
		t.Fatal(err)
	}
	if err := scope.RunContainer(ctx, ContainerSpec{Role: "authority", Image: topologyGoImage, Command: []string{"bash", "-c", "until (:</dev/tcp/postgres/5432) 2>/dev/null; do sleep 0.1; done; while [ ! -x /opt/paperboat-regional-authority.test ]; do sleep 0.05; done; exec /opt/paperboat-regional-authority.test -test.run '^TestSQLRepositoryIssuesReplaysConflictsAndRevokesAtomicPair$' -test.count=1 -test.v"}, Environment: []string{"PAPERBOAT_TEST_DATABASE_DSN=postgres://paperboat:paperboat-test-only@postgres:5432/paperboat_test?sslmode=disable"}, Networks: []string{"database"}, ExtraHosts: map[string]string{"postgres": postgresAddress}, MemoryBytes: 768 << 20, CPUQuota: 100000, PIDs: 256}); err != nil {
		t.Fatal(err)
	}
	if err := scope.UploadExecutable(ctx, "authority", authorityBinary, "/opt/paperboat-regional-authority.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := scope.Wait(ctx, "authority"); err != nil {
		logs, _ := scope.Logs(ctx, "authority", 128<<10)
		t.Fatalf("regional authority topology failed: stdout=%s stderr=%s err=%v", logs.Stdout, logs.Stderr, err)
	}
	logs, err := scope.Logs(ctx, "authority", 128<<10)
	if err != nil || !bytes.Contains(logs.Stdout, []byte("--- PASS: TestSQLRepositoryIssuesReplaysConflictsAndRevokesAtomicPair")) {
		t.Fatalf("regional authority topology evidence missing: logs=%#v err=%v", logs, err)
	}
	if _, err := scope.Close(false); err != nil {
		t.Fatal(err)
	}
	closed = true
}

func TestNetworkFaultInjectionAffectsOwnedUDPAndRecovers(t *testing.T) {
	if os.Getenv("PAPERBOAT_TOPOLOGY_TEST") != "1" {
		t.Skip("set PAPERBOAT_TOPOLOGY_TEST=1 to run Docker fault injection")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	scope := newIntegrationScope(t, ctx, "pbfault")
	closed := false
	t.Cleanup(func() {
		if !closed {
			_, _ = scope.Close(true)
		}
	})
	if err := scope.CreateNetwork(ctx, "peer", true); err != nil {
		t.Fatal(err)
	}
	if err := scope.CreateVolume(ctx, "state"); err != nil {
		t.Fatal(err)
	}
	if err := scope.RunContainer(ctx, ContainerSpec{
		Role: "server", Image: topologyNetToolsImage,
		Command:  []string{"sh", "-c", "touch /state/messages; exec socat -u UDP4-RECVFROM:9000,fork SYSTEM:'cat >> /state/messages'"},
		Networks: []string{"peer"}, Volumes: []VolumeMount{{Role: "state", ContainerPath: "/state"}},
		MemoryBytes: 64 << 20, CPUQuota: 25000, PIDs: 64, NetworkAdmin: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := scope.RunContainer(ctx, ContainerSpec{
		Role: "client", Image: topologyNetToolsImage,
		Command:  []string{"sh", "-c", "while :; do sleep 60; done"},
		Networks: []string{"peer"}, MemoryBytes: 64 << 20, CPUQuota: 25000, PIDs: 64, NetworkAdmin: true,
	}); err != nil {
		t.Fatal(err)
	}
	serverAddress, err := scope.ContainerAddress("server", "peer")
	if err != nil {
		t.Fatal(err)
	}
	send := func(token string) error {
		t.Helper()
		return scope.Exec(ctx, "client", []string{"sh", "-c", "printf %s " + token + " | socat - UDP4-DATAGRAM:" + serverAddress + ":9000"})
	}
	requireSend := func(token string) {
		t.Helper()
		if err := send(token); err != nil {
			t.Fatal(err)
		}
	}
	waitForReceipt := func(token string) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if err := scope.Exec(ctx, "server", []string{"grep", "-Fq", token, "/state/messages"}); err == nil {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatalf("server did not receive %q", token)
	}
	requireNoReceipt := func(token string) {
		t.Helper()
		if err := scope.Exec(ctx, "server", []string{"sh", "-c", "! grep -Fq " + token + " /state/messages"}); err != nil {
			t.Fatalf("server unexpectedly received %q: %v", token, err)
		}
	}
	requireSend("baseline")
	waitForReceipt("baseline")
	if err := scope.SetNetworkImpairment("client", 0, 100); err != nil {
		t.Fatal(err)
	}
	requireSend("dropped")
	time.Sleep(300 * time.Millisecond)
	requireNoReceipt("dropped")
	if err := scope.SetNetworkImpairment("client", 0, 0); err != nil {
		t.Fatal(err)
	}
	requireSend("recovered")
	waitForReceipt("recovered")
	if err := scope.SetUDPBlocked("client", true); err != nil {
		t.Fatal(err)
	}
	if err := send("blocked"); err != nil && !errors.Is(err, ErrCommand) {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	requireNoReceipt("blocked")
	if err := scope.SetUDPBlocked("client", false); err != nil {
		t.Fatal(err)
	}
	requireSend("unblocked")
	waitForReceipt("unblocked")
	report, err := scope.Close(true)
	if err != nil {
		t.Fatal(err)
	}
	closed = true
	if report.RemovedContainers != 2 || report.RemovedNetworks != 1 || report.RemovedVolumes != 1 {
		t.Fatalf("cleanup=%+v", report)
	}
}

func TestOwnedTunnelSTUNAcrossIsolatedContainers(t *testing.T) {
	if os.Getenv("PAPERBOAT_TOPOLOGY_TEST") != "1" {
		t.Skip("set PAPERBOAT_TOPOLOGY_TEST=1 to run Docker topology integration")
	}
	binary := os.Getenv("PAPERBOAT_TOPOLOGY_STUN_BINARY")
	if binary == "" {
		t.Skip("set PAPERBOAT_TOPOLOGY_STUN_BINARY to the Linux tunnel STUN test executable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	scope := newIntegrationScope(t, ctx, "pbstun")
	closed := false
	t.Cleanup(func() {
		if !closed {
			_, _ = scope.Close(true)
		}
	})
	if err := scope.CreateNetwork(ctx, "peer", true); err != nil {
		t.Fatal(err)
	}
	processCommand := []string{"sh", "-c", "while [ ! -x /opt/paperboat-stun-test ]; do sleep 0.05; done; exec /opt/paperboat-stun-test -test.run '^TestTopologyProcess$' -test.v"}
	if err := scope.RunContainer(ctx, ContainerSpec{
		Role: "stun", Image: topologyGoImage, Command: processCommand,
		Environment: []string{"PAPERBOAT_TOPOLOGY_ROLE=server"}, Networks: []string{"peer"},
		MemoryBytes: 64 << 20, CPUQuota: 25000, PIDs: 32, ReadOnlyRoot: false,
	}); err != nil {
		t.Fatal(err)
	}
	if err := scope.UploadExecutable(ctx, "stun", binary, "/opt/paperboat-stun-test"); err != nil {
		t.Fatal(err)
	}
	serverAddress, err := scope.ContainerAddress("stun", "peer")
	if err != nil {
		t.Fatal(err)
	}
	if err := scope.RunContainer(ctx, ContainerSpec{
		Role: "client", Image: topologyGoImage, Command: processCommand,
		Environment: []string{"PAPERBOAT_TOPOLOGY_ROLE=client", "PAPERBOAT_TOPOLOGY_STUN_TARGET=" + net.JoinHostPort(serverAddress, "3478")}, Networks: []string{"peer"},
		MemoryBytes: 64 << 20, CPUQuota: 25000, PIDs: 32, ReadOnlyRoot: false,
	}); err != nil {
		t.Fatal(err)
	}
	if err := scope.UploadExecutable(ctx, "client", binary, "/opt/paperboat-stun-test"); err != nil {
		t.Fatal(err)
	}
	exit, err := scope.Wait(ctx, "client")
	if err != nil || exit != 0 {
		logs, _ := scope.Logs(ctx, "client", 64<<10)
		t.Fatalf("STUN client exit=%d err=%v logs=%q %q", exit, err, logs.Stdout, logs.Stderr)
	}
	for _, role := range []string{"stun", "client"} {
		logs, err := scope.Logs(ctx, role, 64<<10)
		if err != nil {
			t.Fatal(err)
		}
		marker := "PAPERBOAT_TOPOLOGY_STUN_READY"
		if role == "client" {
			marker = "PAPERBOAT_TOPOLOGY_STUN_OK"
		}
		if !bytes.Contains(logs.Stdout, []byte(marker)) || logs.Truncated {
			t.Fatalf("%s logs missing marker %q: %#v", role, marker, logs)
		}
	}
	if _, err := scope.Sample(ctx, "stun"); err != nil {
		t.Fatal(err)
	}
	report, err := scope.Close(true)
	if err != nil {
		t.Fatal(err)
	}
	closed = true
	if report.RemovedContainers != 2 || report.RemovedNetworks != 1 {
		t.Fatalf("cleanup = %#v", report)
	}
}

func TestAuthenticatedICEAndDirectQUICBypassTunnel(t *testing.T) {
	if os.Getenv("PAPERBOAT_TOPOLOGY_TEST") != "1" {
		t.Skip("set PAPERBOAT_TOPOLOGY_TEST=1 to run Docker topology integration")
	}
	tunnelBinary := os.Getenv("PAPERBOAT_TOPOLOGY_STUN_BINARY")
	endpointBinary := os.Getenv("PAPERBOAT_TOPOLOGY_ENDPOINT_BINARY")
	if tunnelBinary == "" || endpointBinary == "" {
		t.Skip("set topology tunnel and endpoint test executables")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	scope := newIntegrationScope(t, ctx, "pbice")
	closed := false
	t.Cleanup(func() {
		if !closed {
			_, _ = scope.Close(true)
		}
	})
	if err := scope.CreateNetwork(ctx, "peer", true); err != nil {
		t.Fatal(err)
	}
	processCommand := func(binary string) []string {
		return []string{"sh", "-c", "while [ ! -x '" + binary + "' ]; do sleep 0.05; done; exec '" + binary + "' -test.run '^TestTopologyEndpointProcess$' -test.v"}
	}
	if err := scope.RunContainer(ctx, ContainerSpec{Role: "edge", Image: topologyGoImage, Command: []string{"sh", "-c", "while [ ! -x /opt/paperboat-edge-test ]; do sleep 0.05; done; exec /opt/paperboat-edge-test -test.run '^TestTopologyProcess$' -test.v"}, Environment: []string{"PAPERBOAT_TOPOLOGY_ROLE=edge"}, Networks: []string{"peer"}, MemoryBytes: 96 << 20, CPUQuota: 30000, PIDs: 48}); err != nil {
		t.Fatal(err)
	}
	if err := scope.UploadExecutable(ctx, "edge", tunnelBinary, "/opt/paperboat-edge-test"); err != nil {
		t.Fatal(err)
	}
	edgeAddress, err := scope.ContainerAddress("edge", "peer")
	if err != nil {
		t.Fatal(err)
	}
	endpointEnv := func(role string) []string {
		return []string{"PAPERBOAT_TOPOLOGY_ENDPOINT_ROLE=" + role, "PAPERBOAT_TOPOLOGY_SIGNALING_URL=wss://signaling.paperboat.test:8443/v1/peer-signaling", "PAPERBOAT_TOPOLOGY_STUN_URL=stun:" + net.JoinHostPort(edgeAddress, "3478"), "PAPERBOAT_TOPOLOGY_QUIC_GATE=/tmp/paperboat-quic-start", "PAPERBOAT_TOPOLOGY_QUIC_RECOVERY_GATE=/tmp/paperboat-quic-recovery"}
	}
	for _, endpoint := range []struct{ role, name string }{{"controlling", "client"}, {"controlled", "host"}} {
		if err := scope.RunContainer(ctx, ContainerSpec{Role: endpoint.name, Image: topologyNetToolsImage, Command: processCommand("/opt/paperboat-endpoint-test"), Environment: endpointEnv(endpoint.role), Networks: []string{"peer"}, ExtraHosts: map[string]string{"signaling.paperboat.test": edgeAddress}, MemoryBytes: 96 << 20, CPUQuota: 30000, PIDs: 48, NetworkAdmin: endpoint.name == "client"}); err != nil {
			t.Fatal(err)
		}
		if err := scope.UploadExecutable(ctx, endpoint.name, endpointBinary, "/opt/paperboat-endpoint-test"); err != nil {
			t.Fatal(err)
		}
	}
	waitForLogMarker := func(role, marker string) {
		t.Helper()
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		for {
			logs, err := scope.Logs(ctx, role, 64<<10)
			if err == nil && bytes.Contains(logs.Stdout, []byte(marker)) {
				return
			}
			if err == nil && (bytes.Contains(logs.Stdout, []byte("--- FAIL:")) || bytes.Contains(logs.Stderr, []byte("--- FAIL:"))) {
				all := make(map[string]ContainerLogs, 3)
				for _, current := range []string{"edge", "client", "host"} {
					all[current], _ = scope.Logs(ctx, current, 64<<10)
				}
				t.Fatalf("%s failed before marker %q: logs=%#v", role, marker, all)
			}
			select {
			case <-ctx.Done():
				t.Fatalf("waiting for %s marker %q: %v", role, marker, ctx.Err())
			case <-ticker.C:
			}
		}
	}
	waitForLogMarker("edge", "PAPERBOAT_TOPOLOGY_EDGE_READY")
	waitForLogMarker("client", "PAPERBOAT_TOPOLOGY_ICE_OK role=controlling")
	waitForLogMarker("host", "PAPERBOAT_TOPOLOGY_ICE_OK role=controlled")
	if err := scope.Disconnect(ctx, "edge", "peer"); err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range []string{"client", "host"} {
		if err := scope.Exec(ctx, endpoint, []string{"touch", "/tmp/paperboat-quic-start"}); err != nil {
			t.Fatal(err)
		}
	}
	waitForLogMarker("client", "PAPERBOAT_TOPOLOGY_CONTROLLING_BASELINE_OK")
	waitForLogMarker("host", "PAPERBOAT_TOPOLOGY_CONTROLLED_BASELINE_OK")
	if err := scope.SetUDPBlocked("client", true); err != nil {
		t.Fatal(err)
	}
	if err := scope.Exec(ctx, "client", []string{"touch", "/tmp/paperboat-quic-recovery"}); err != nil {
		t.Fatal(err)
	}
	waitForLogMarker("client", "PAPERBOAT_TOPOLOGY_RECOVERY_SEND_STARTED")
	time.Sleep(500 * time.Millisecond)
	for _, endpoint := range []struct{ name, marker string }{{"client", "PAPERBOAT_TOPOLOGY_CONTROLLING_QUIC_OK"}, {"host", "PAPERBOAT_TOPOLOGY_CONTROLLED_QUIC_OK"}} {
		logs, err := scope.Logs(ctx, endpoint.name, 64<<10)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(logs.Stdout, []byte(endpoint.marker)) {
			t.Fatalf("%s completed while outbound UDP was blocked", endpoint.name)
		}
	}
	if err := scope.SetUDPBlocked("client", false); err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range []struct{ name, marker string }{{"client", "PAPERBOAT_TOPOLOGY_CONTROLLING_QUIC_OK"}, {"host", "PAPERBOAT_TOPOLOGY_CONTROLLED_QUIC_OK"}} {
		exit, err := scope.Wait(ctx, endpoint.name)
		if err != nil || exit != 0 {
			logs, _ := scope.Logs(ctx, endpoint.name, 64<<10)
			t.Fatalf("%s exit=%d err=%v logs=%q %q", endpoint.name, exit, err, logs.Stdout, logs.Stderr)
		}
		logs, err := scope.Logs(ctx, endpoint.name, 64<<10)
		if err != nil || !bytes.Contains(logs.Stdout, []byte(endpoint.marker)) || logs.Truncated {
			t.Fatalf("%s logs=%#v error=%v", endpoint.name, logs, err)
		}
	}
	if _, err := scope.Sample(ctx, "edge"); err != nil {
		t.Fatal(err)
	}
	report, err := scope.Close(true)
	if err != nil {
		t.Fatal(err)
	}
	closed = true
	if report.RemovedContainers != 3 || report.RemovedNetworks != 1 {
		t.Fatalf("cleanup = %#v", report)
	}
}

func TestAuthenticatedNoiseRelayQUICAcrossEdge(t *testing.T) {
	runAuthenticatedNoiseRelayTopology(t, relayTopologyConfig{
		prefix: "pbrelay", url: "https://relay.paperboat.test:9443/v1/peer-relay",
		initiatorRole: "relay-initiator", responderRole: "relay-responder",
		initiatorMarker: "PAPERBOAT_TOPOLOGY_RELAY_INITIATOR_OK", responderMarker: "PAPERBOAT_TOPOLOGY_RELAY_RESPONDER_OK",
	})
}

func TestAuthenticatedNoiseWSSAcrossEdge(t *testing.T) {
	runAuthenticatedNoiseRelayTopology(t, relayTopologyConfig{
		prefix: "pbwss", url: "wss://relay.paperboat.test:9444/v1/peer-relay",
		initiatorRole: "wss-initiator", responderRole: "wss-responder",
		initiatorMarker: "PAPERBOAT_TOPOLOGY_WSS_INITIATOR_OK", responderMarker: "PAPERBOAT_TOPOLOGY_WSS_RESPONDER_OK",
		blockUDP: true,
	})
}

func TestAutoSelectsAuthenticatedNoiseRelayQUIC(t *testing.T) {
	runAuthenticatedNoiseRelayTopology(t, relayTopologyConfig{
		prefix: "pbautorelay", url: "https://relay.paperboat.test:9443/v1/peer-relay",
		initiatorRole: "auto-relay-initiator", responderRole: "health-relay-responder",
		initiatorMarker: "PAPERBOAT_TOPOLOGY_AUTO_RELAY_OK", responderMarker: "PAPERBOAT_TOPOLOGY_RELAY_RESPONDER_OK",
	})
}

func TestAutoSelectsAuthenticatedNoiseWSSWhenUDPBlocked(t *testing.T) {
	runAuthenticatedNoiseRelayTopology(t, relayTopologyConfig{
		prefix: "pbautowss", url: "wss://relay.paperboat.test:9444/v1/peer-relay",
		initiatorRole: "auto-wss-initiator", responderRole: "health-wss-responder",
		initiatorMarker: "PAPERBOAT_TOPOLOGY_AUTO_WSS_OK", responderMarker: "PAPERBOAT_TOPOLOGY_WSS_RESPONDER_OK",
		blockUDP: true,
	})
}

func TestHostPeerRelayServiceLifecycleAcrossWSS(t *testing.T) {
	runAuthenticatedNoiseRelayTopology(t, relayTopologyConfig{
		prefix: "pbhostservice", url: "wss://relay.paperboat.test:9444/v1/peer-relay",
		initiatorRole: "service-wss-initiator", responderRole: "service-wss-responder",
		initiatorMarker: "PAPERBOAT_TOPOLOGY_HOST_SERVICE_CLIENT_OK", responderMarker: "PAPERBOAT_TOPOLOGY_HOST_SERVICE_WSS_OK",
		blockUDP: true, hostService: true,
	})
}

func TestPeerTerminalPingUsesProductionWSSConnector(t *testing.T) {
	runAuthenticatedNoiseRelayTopology(t, relayTopologyConfig{
		prefix: "pbterminalping", url: "wss://relay.paperboat.test:9444/v1/peer-relay",
		initiatorRole: "terminal-ping-wss-initiator", responderRole: "terminal-ping-wss-responder",
		initiatorMarker: "PAPERBOAT_TOPOLOGY_PEER_TERMINAL_PING_OK", responderMarker: "PAPERBOAT_TOPOLOGY_TERMINAL_PING_HOST_OK",
		blockUDP: true, hostService: true, terminalPing: true,
	})
}

func TestPeerTerminalWorkflowUsesProductionWSSConnector(t *testing.T) {
	runAuthenticatedNoiseRelayTopology(t, relayTopologyConfig{
		prefix: "pbterminal", url: "wss://relay.paperboat.test:9444/v1/peer-relay",
		initiatorRole: "terminal-wss-initiator", responderRole: "terminal-wss-responder",
		initiatorMarker: "PAPERBOAT_TOPOLOGY_PEER_TERMINAL_OK", responderMarker: "PAPERBOAT_TOPOLOGY_TERMINAL_HOST_OK",
		blockUDP: true, hostService: true, terminalPing: true, terminalWorkflow: true,
	})
}

func TestPeerTerminalCancellationUsesProductionWSSConnector(t *testing.T) {
	runAuthenticatedNoiseRelayTopology(t, relayTopologyConfig{
		prefix: "pbterminalcancel", url: "wss://relay.paperboat.test:9444/v1/peer-relay",
		initiatorRole: "terminal-cancel-wss-initiator", responderRole: "terminal-cancel-wss-responder",
		initiatorMarker: "PAPERBOAT_TOPOLOGY_PEER_TERMINAL_CANCEL_OK", responderMarker: "PAPERBOAT_TOPOLOGY_TERMINAL_HOST_OK",
		blockUDP: true, hostService: true, terminalPing: true, terminalWorkflow: true, cancellation: true,
	})
}

func TestPeerTerminalCancellationUsesProductionRelayQUICConnector(t *testing.T) {
	runAuthenticatedNoiseRelayTopology(t, relayTopologyConfig{
		prefix: "pbterminalcancelrelay", url: "https://relay.paperboat.test:9443/v1/peer-relay",
		initiatorRole: "terminal-cancel-relay-quic-initiator", responderRole: "terminal-cancel-relay-quic-responder",
		initiatorMarker: "PAPERBOAT_TOPOLOGY_PEER_TERMINAL_CANCEL_OK", responderMarker: "PAPERBOAT_TOPOLOGY_TERMINAL_HOST_OK",
		hostService: true, terminalPing: true, terminalWorkflow: true, terminalCarrier: "relay-quic", cancellation: true,
	})
}

func TestPeerTerminalCancellationUsesProductionDirectQUICConnector(t *testing.T) {
	runAuthenticatedNoiseRelayTopology(t, relayTopologyConfig{
		prefix: "pbterminalcanceldirect", url: "wss://relay.paperboat.test:9444/v1/peer-relay",
		initiatorRole: "terminal-cancel-direct-quic-initiator", responderRole: "terminal-cancel-direct-quic-responder",
		initiatorMarker: "PAPERBOAT_TOPOLOGY_PEER_TERMINAL_CANCEL_OK", responderMarker: "PAPERBOAT_TOPOLOGY_TERMINAL_HOST_OK",
		hostService: true, terminalPing: true, terminalWorkflow: true, terminalCarrier: "direct-quic", forbidRelay: true, cancellation: true,
	})
}

func TestPeerTerminalWorkflowUsesProductionRelayQUICConnector(t *testing.T) {
	runAuthenticatedNoiseRelayTopology(t, relayTopologyConfig{
		prefix: "pbterminalrelay", url: "https://relay.paperboat.test:9443/v1/peer-relay",
		initiatorRole: "terminal-relay-quic-initiator", responderRole: "terminal-relay-quic-responder",
		initiatorMarker: "PAPERBOAT_TOPOLOGY_PEER_TERMINAL_OK", responderMarker: "PAPERBOAT_TOPOLOGY_TERMINAL_HOST_OK",
		hostService: true, terminalPing: true, terminalWorkflow: true, terminalCarrier: "relay-quic",
	})
}

func TestPeerTerminalWorkflowUsesProductionDirectQUICConnector(t *testing.T) {
	runAuthenticatedNoiseRelayTopology(t, relayTopologyConfig{
		prefix: "pbterminaldirect", url: "wss://relay.paperboat.test:9444/v1/peer-relay",
		initiatorRole: "terminal-direct-quic-initiator", responderRole: "terminal-direct-quic-responder",
		initiatorMarker: "PAPERBOAT_TOPOLOGY_PEER_TERMINAL_OK", responderMarker: "PAPERBOAT_TOPOLOGY_TERMINAL_HOST_OK",
		hostService: true, terminalPing: true, terminalWorkflow: true, terminalCarrier: "direct-quic", forbidRelay: true,
	})
}

func TestPeerExecUsesProductionWSSConnector(t *testing.T) {
	runAuthenticatedNoiseRelayTopology(t, relayTopologyConfig{
		prefix: "pbexecwss", url: "wss://relay.paperboat.test:9444/v1/peer-relay",
		initiatorRole: "exec-wss-initiator", responderRole: "exec-wss-responder",
		initiatorMarker: "PAPERBOAT_TOPOLOGY_PEER_EXEC_OK", responderMarker: "PAPERBOAT_TOPOLOGY_TERMINAL_HOST_OK",
		blockUDP: true, hostService: true, terminalPing: true, execWorkflow: true,
	})
}

func TestPeerExecUsesProductionRelayQUICConnector(t *testing.T) {
	runAuthenticatedNoiseRelayTopology(t, relayTopologyConfig{
		prefix: "pbexecrelay", url: "https://relay.paperboat.test:9443/v1/peer-relay",
		initiatorRole: "exec-relay-quic-initiator", responderRole: "exec-relay-quic-responder",
		initiatorMarker: "PAPERBOAT_TOPOLOGY_PEER_EXEC_OK", responderMarker: "PAPERBOAT_TOPOLOGY_TERMINAL_HOST_OK",
		hostService: true, terminalPing: true, terminalCarrier: "relay-quic", execWorkflow: true,
	})
}

func TestPeerExecUsesProductionDirectQUICConnector(t *testing.T) {
	runAuthenticatedNoiseRelayTopology(t, relayTopologyConfig{
		prefix: "pbexecdirect", url: "wss://relay.paperboat.test:9444/v1/peer-relay",
		initiatorRole: "exec-direct-quic-initiator", responderRole: "exec-direct-quic-responder",
		initiatorMarker: "PAPERBOAT_TOPOLOGY_PEER_EXEC_OK", responderMarker: "PAPERBOAT_TOPOLOGY_TERMINAL_HOST_OK",
		hostService: true, terminalPing: true, terminalCarrier: "direct-quic", forbidRelay: true, execWorkflow: true,
	})
}

func TestPeerSSHUsesProductionWSSConnector(t *testing.T) {
	runAuthenticatedNoiseRelayTopology(t, relayTopologyConfig{
		prefix: "pbsshwss", url: "wss://relay.paperboat.test:9444/v1/peer-relay",
		initiatorRole: "ssh-wss-initiator", responderRole: "ssh-wss-responder",
		initiatorMarker: "PAPERBOAT_TOPOLOGY_PEER_SSH_OK", responderMarker: "PAPERBOAT_TOPOLOGY_SSH_HOST_OK",
		blockUDP: true, hostService: true, terminalPing: true, sshWorkflow: true,
	})
}

func TestPeerSSHUsesProductionRelayQUICConnector(t *testing.T) {
	runAuthenticatedNoiseRelayTopology(t, relayTopologyConfig{
		prefix: "pbsshrelay", url: "https://relay.paperboat.test:9443/v1/peer-relay",
		initiatorRole: "ssh-relay-quic-initiator", responderRole: "ssh-relay-quic-responder",
		initiatorMarker: "PAPERBOAT_TOPOLOGY_PEER_SSH_OK", responderMarker: "PAPERBOAT_TOPOLOGY_SSH_HOST_OK",
		hostService: true, terminalPing: true, terminalCarrier: "relay-quic", sshWorkflow: true,
	})
}

func TestPeerSSHUsesProductionDirectQUICConnector(t *testing.T) {
	runAuthenticatedNoiseRelayTopology(t, relayTopologyConfig{
		prefix: "pbsshdirect", url: "wss://relay.paperboat.test:9444/v1/peer-relay",
		initiatorRole: "ssh-direct-quic-initiator", responderRole: "ssh-direct-quic-responder",
		initiatorMarker: "PAPERBOAT_TOPOLOGY_PEER_SSH_OK", responderMarker: "PAPERBOAT_TOPOLOGY_SSH_HOST_OK",
		hostService: true, terminalPing: true, terminalCarrier: "direct-quic", forbidRelay: true, sshWorkflow: true,
	})
}

func TestPeerCodexUsesProductionWSSConnector(t *testing.T) {
	runAuthenticatedNoiseRelayTopology(t, relayTopologyConfig{
		prefix: "pbcodexwss", url: "wss://relay.paperboat.test:9444/v1/peer-relay",
		initiatorRole: "codex-wss-initiator", responderRole: "codex-wss-responder",
		initiatorMarker: "PAPERBOAT_TOPOLOGY_PEER_CODEX_OK", responderMarker: "PAPERBOAT_TOPOLOGY_CODEX_HOST_OK",
		blockUDP: true, hostService: true, terminalPing: true, codexWorkflow: true,
	})
}

func TestPeerCodexUsesProductionRelayQUICConnector(t *testing.T) {
	runAuthenticatedNoiseRelayTopology(t, relayTopologyConfig{
		prefix: "pbcodexrelay", url: "https://relay.paperboat.test:9443/v1/peer-relay",
		initiatorRole: "codex-relay-quic-initiator", responderRole: "codex-relay-quic-responder",
		initiatorMarker: "PAPERBOAT_TOPOLOGY_PEER_CODEX_OK", responderMarker: "PAPERBOAT_TOPOLOGY_CODEX_HOST_OK",
		hostService: true, terminalPing: true, terminalCarrier: "relay-quic", codexWorkflow: true,
	})
}

func TestPeerCodexUsesProductionDirectQUICConnector(t *testing.T) {
	runAuthenticatedNoiseRelayTopology(t, relayTopologyConfig{
		prefix: "pbcodexdirect", url: "wss://relay.paperboat.test:9444/v1/peer-relay",
		initiatorRole: "codex-direct-quic-initiator", responderRole: "codex-direct-quic-responder",
		initiatorMarker: "PAPERBOAT_TOPOLOGY_PEER_CODEX_OK", responderMarker: "PAPERBOAT_TOPOLOGY_CODEX_HOST_OK",
		hostService: true, terminalPing: true, terminalCarrier: "direct-quic", forbidRelay: true, codexWorkflow: true,
	})
}

func TestPeerPrivatePreviewUsesProductionWSSConnector(t *testing.T) {
	runAuthenticatedNoiseRelayTopology(t, relayTopologyConfig{
		prefix: "pbpreviewwss", url: "wss://relay.paperboat.test:9444/v1/peer-relay",
		initiatorRole: "preview-wss-initiator", responderRole: "preview-wss-responder",
		initiatorMarker: "PAPERBOAT_TOPOLOGY_PEER_PREVIEW_OK", responderMarker: "PAPERBOAT_TOPOLOGY_PREVIEW_HOST_OK",
		blockUDP: true, hostService: true, terminalPing: true, privatePreviewWorkflow: true,
	})
}

func TestPeerPrivatePreviewUsesProductionRelayQUICConnector(t *testing.T) {
	runAuthenticatedNoiseRelayTopology(t, relayTopologyConfig{
		prefix: "pbpreviewrelay", url: "https://relay.paperboat.test:9443/v1/peer-relay",
		initiatorRole: "preview-relay-quic-initiator", responderRole: "preview-relay-quic-responder",
		initiatorMarker: "PAPERBOAT_TOPOLOGY_PEER_PREVIEW_OK", responderMarker: "PAPERBOAT_TOPOLOGY_PREVIEW_HOST_OK",
		hostService: true, terminalPing: true, terminalCarrier: "relay-quic", privatePreviewWorkflow: true,
	})
}

func TestPeerPrivatePreviewUsesProductionDirectQUICConnector(t *testing.T) {
	runAuthenticatedNoiseRelayTopology(t, relayTopologyConfig{
		prefix: "pbpreviewdirect", url: "wss://relay.paperboat.test:9444/v1/peer-relay",
		initiatorRole: "preview-direct-quic-initiator", responderRole: "preview-direct-quic-responder",
		initiatorMarker: "PAPERBOAT_TOPOLOGY_PEER_PREVIEW_OK", responderMarker: "PAPERBOAT_TOPOLOGY_PREVIEW_HOST_OK",
		hostService: true, terminalPing: true, terminalCarrier: "direct-quic", forbidRelay: true, privatePreviewWorkflow: true,
	})
}

func TestPeerFileTransferUsesProductionDirectQUICConnector(t *testing.T) {
	runAuthenticatedNoiseRelayTopology(t, relayTopologyConfig{
		prefix: "pbfiledirect", url: "wss://relay.paperboat.test:9444/v1/peer-relay",
		initiatorRole: "file-direct-quic-initiator", responderRole: "file-direct-quic-responder",
		initiatorMarker: "PAPERBOAT_TOPOLOGY_PEER_FILE_DIRECT_OK", responderMarker: "PAPERBOAT_TOPOLOGY_TERMINAL_HOST_OK",
		hostService: true, terminalPing: true, terminalCarrier: "direct-quic", forbidRelay: true, fileWorkflow: true,
	})
}

func TestPeerFileTransferUsesProductionRelayHTTP3(t *testing.T) {
	runAuthenticatedNoiseRelayTopology(t, relayTopologyConfig{
		prefix: "pbfileh3", url: "wss://relay.paperboat.test:9444/v1/peer-relay",
		initiatorRole: "file-relay-h3-initiator", responderRole: "file-relay-h3-responder",
		initiatorMarker: "PAPERBOAT_TOPOLOGY_PEER_FILE_H3_OK", responderMarker: "PAPERBOAT_TOPOLOGY_TERMINAL_HOST_OK",
		hostService: true, terminalPing: true, fileWorkflow: true, fileRelay: true, fileCarrier: "HTTP/3.0",
	})
}

func TestPeerReverseFileTransferUsesProductionRelayHTTP3(t *testing.T) {
	runAuthenticatedNoiseRelayTopology(t, relayTopologyConfig{
		prefix: "pbreversefileh3", url: "wss://relay.paperboat.test:9444/v1/peer-relay",
		initiatorRole: "file-reverse-relay-h3-initiator", responderRole: "file-reverse-relay-h3-responder",
		initiatorMarker: "PAPERBOAT_TOPOLOGY_PEER_FILE_REVERSE_H3_OK", responderMarker: "PAPERBOAT_TOPOLOGY_TERMINAL_HOST_OK",
		hostService: true, terminalPing: true, reverseFileWorkflow: true, fileRelay: true, fileCarrier: "HTTP/3.0",
	})
}

func TestPeerReverseFileTransferPromotesToProductionDirectQUIC(t *testing.T) {
	runAuthenticatedNoiseRelayTopology(t, relayTopologyConfig{
		prefix: "pbreversefiledirect", url: "wss://relay.paperboat.test:9444/v1/peer-relay",
		initiatorRole: "file-reverse-direct-quic-initiator", responderRole: "file-reverse-direct-quic-responder",
		initiatorMarker: "PAPERBOAT_TOPOLOGY_PEER_FILE_REVERSE_DIRECT_OK", responderMarker: "PAPERBOAT_TOPOLOGY_TERMINAL_HOST_OK",
		hostService: true, terminalPing: true, terminalCarrier: "direct-quic", forbidRelay: true, reverseFileWorkflow: true, fileRelay: true, fileCarrier: "HTTP/3.0",
	})
}

func TestPeerReverseFileTransferFallsBackToProductionRelayHTTP2(t *testing.T) {
	runAuthenticatedNoiseRelayTopology(t, relayTopologyConfig{
		prefix: "pbreversefileh2", url: "wss://relay.paperboat.test:9444/v1/peer-relay",
		initiatorRole: "file-reverse-relay-h2-initiator", responderRole: "file-reverse-relay-h2-responder",
		initiatorMarker: "PAPERBOAT_TOPOLOGY_PEER_FILE_REVERSE_H2_OK", responderMarker: "PAPERBOAT_TOPOLOGY_TERMINAL_HOST_OK",
		hostService: true, terminalPing: true, reverseFileWorkflow: true, fileRelay: true, fileCarrier: "HTTP/2.0",
	})
}

func TestPeerFileTransferFallsBackToProductionRelayHTTP2(t *testing.T) {
	runAuthenticatedNoiseRelayTopology(t, relayTopologyConfig{
		prefix: "pbfileh2", url: "wss://relay.paperboat.test:9444/v1/peer-relay",
		initiatorRole: "file-relay-h2-initiator", responderRole: "file-relay-h2-responder",
		initiatorMarker: "PAPERBOAT_TOPOLOGY_PEER_FILE_H2_OK", responderMarker: "PAPERBOAT_TOPOLOGY_TERMINAL_HOST_OK",
		hostService: true, terminalPing: true, fileWorkflow: true, fileRelay: true, fileCarrier: "HTTP/2.0",
	})
}

type relayTopologyConfig struct {
	prefix, url, initiatorRole, responderRole, initiatorMarker, responderMarker string
	blockUDP                                                                    bool
	hostService                                                                 bool
	terminalPing                                                                bool
	terminalWorkflow                                                            bool
	terminalCarrier                                                             string
	forbidRelay                                                                 bool
	cancellation                                                                bool
	execWorkflow                                                                bool
	sshWorkflow                                                                 bool
	codexWorkflow                                                               bool
	privatePreviewWorkflow                                                      bool
	fileWorkflow                                                                bool
	reverseFileWorkflow                                                         bool
	fileRelay                                                                   bool
	fileCarrier                                                                 string
}

func runAuthenticatedNoiseRelayTopology(t *testing.T, topology relayTopologyConfig) {
	t.Helper()
	if os.Getenv("PAPERBOAT_TOPOLOGY_TEST") != "1" {
		t.Skip("set PAPERBOAT_TOPOLOGY_TEST=1 to run Docker relay integration")
	}
	relayBinary := os.Getenv("PAPERBOAT_TOPOLOGY_RELAY_BINARY")
	endpointBinary := os.Getenv("PAPERBOAT_TOPOLOGY_ENDPOINT_BINARY")
	if relayBinary == "" || endpointBinary == "" {
		t.Skip("set topology relay and endpoint test executables")
	}
	hostBinary := os.Getenv("PAPERBOAT_TOPOLOGY_HOST_BINARY")
	if topology.hostService && hostBinary == "" {
		t.Skip("set topology host test executable")
	}
	terminalBinary := os.Getenv("PAPERBOAT_TOPOLOGY_TERMINAL_BINARY")
	if topology.terminalPing && terminalBinary == "" {
		t.Skip("set topology peer terminal test executable")
	}
	authorityBinary := os.Getenv("PAPERBOAT_TOPOLOGY_AUTHORITY_BINARY")
	if topology.terminalPing && authorityBinary == "" {
		t.Skip("set topology authority test executable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var rsyncPackages []string
	if topology.sshWorkflow {
		rsyncPackages = fetchTopologyRsyncPackages(t, ctx)
	}
	scope := newIntegrationScope(t, ctx, topology.prefix)
	closed := false
	t.Cleanup(func() {
		if !closed {
			_, _ = scope.Close(true)
		}
	})
	relayInternal := topology.terminalCarrier != "relay-quic" && topology.terminalCarrier != "direct-quic"
	isolatedRelay := topology.terminalCarrier != "direct-quic"
	edgeNetworks := []string{"relay"}
	clientNetworks := []string{"relay"}
	hostNetworks := []string{"relay"}
	clientEdgeNetwork, hostEdgeNetwork, controlNetwork := "relay", "relay", "relay"
	if isolatedRelay {
		clientEdgeNetwork, hostEdgeNetwork = "client-edge", "host-edge"
		edgeNetworks = []string{clientEdgeNetwork, hostEdgeNetwork}
		clientNetworks = []string{clientEdgeNetwork}
		hostNetworks = []string{hostEdgeNetwork}
		for _, network := range edgeNetworks {
			if err := scope.CreateNetwork(ctx, network, relayInternal); err != nil {
				t.Fatal(err)
			}
		}
	} else if err := scope.CreateNetwork(ctx, "relay", relayInternal); err != nil {
		t.Fatal(err)
	}
	if topology.terminalPing {
		if err := scope.CreateNetwork(ctx, "database", true); err != nil {
			t.Fatal(err)
		}
		if isolatedRelay {
			controlNetwork = "client-control"
			clientNetworks = append(clientNetworks, controlNetwork)
			if err := scope.CreateNetwork(ctx, controlNetwork, true); err != nil {
				t.Fatal(err)
			}
		}
	}
	if topology.hostService {
		if err := scope.CreateVolume(ctx, "authority"); err != nil {
			t.Fatal(err)
		}
	}
	edgeEnvironment := []string{"PAPERBOAT_TOPOLOGY_ROLE=relay-edge"}
	if topology.fileRelay {
		edgeEnvironment = append(edgeEnvironment, "PAPERBOAT_TOPOLOGY_FILE_RELAY=1", "PAPERBOAT_TOPOLOGY_FILE_UPSTREAM="+scope.resourceName("container", "host")+":8080")
	}
	if err := scope.RunContainer(ctx, ContainerSpec{
		Role: "edge", Image: topologyGoImage,
		Command:     []string{"sh", "-c", "while [ ! -x /opt/paperboat-relay-test ]; do sleep 0.05; done; exec /opt/paperboat-relay-test -test.run '^TestTopologyRelayProcess$' -test.v"},
		Environment: edgeEnvironment, Networks: edgeNetworks,
		MemoryBytes: 96 << 20, CPUQuota: 30000, PIDs: 64,
	}); err != nil {
		t.Fatal(err)
	}
	if err := scope.UploadExecutable(ctx, "edge", relayBinary, "/opt/paperboat-relay-test"); err != nil {
		t.Fatal(err)
	}
	clientEdgeAddress, err := scope.ContainerAddress("edge", clientEdgeNetwork)
	if err != nil {
		t.Fatal(err)
	}
	hostEdgeAddress, err := scope.ContainerAddress("edge", hostEdgeNetwork)
	if err != nil {
		t.Fatal(err)
	}
	var authorityAddress string
	if topology.terminalPing {
		if err := scope.RunContainer(ctx, ContainerSpec{Role: "postgres", Image: topologyPostgresImage, Command: []string{"postgres"}, Environment: []string{"POSTGRES_PASSWORD=postgres", "POSTGRES_DB=paperboat"}, Networks: []string{"database"}, MemoryBytes: 512 << 20, CPUQuota: 100000, PIDs: 128}); err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(45 * time.Second)
		for time.Now().Before(deadline) {
			if err := scope.Exec(ctx, "postgres", []string{"psql", "-U", "postgres", "-d", "paperboat", "-Atqc", "SELECT 1"}); err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if err := scope.Exec(ctx, "postgres", []string{"psql", "-U", "postgres", "-d", "paperboat", "-Atqc", "SELECT 1"}); err != nil {
			logs, _ := scope.Logs(ctx, "postgres", 64<<10)
			t.Fatalf("postgres did not become ready: stdout=%q stderr=%q", logs.Stdout, logs.Stderr)
		}
		postgresAddress, addressErr := scope.ContainerAddress("postgres", "database")
		if addressErr != nil {
			t.Fatal(addressErr)
		}
		authorityCompletion := "ping"
		if topology.terminalWorkflow {
			authorityCompletion = "terminal"
		} else if topology.execWorkflow {
			authorityCompletion = "exec"
		} else if topology.sshWorkflow {
			authorityCompletion = "ssh"
		} else if topology.codexWorkflow {
			authorityCompletion = "codex"
		} else if topology.privatePreviewWorkflow {
			authorityCompletion = "preview"
		} else if topology.fileWorkflow || topology.reverseFileWorkflow {
			authorityCompletion = "file"
		}
		relayPort := "9444"
		if topology.terminalCarrier == "relay-quic" {
			relayPort = "9443"
		}
		authorityEnvironment := []string{"PAPERBOAT_TOPOLOGY_AUTHORITY_ROLE=peer-authority", "PAPERBOAT_TOPOLOGY_AUTHORITY_COMPLETION=" + authorityCompletion, "PAPERBOAT_TOPOLOGY_AUTHORITY_CARRIER=" + topology.terminalCarrier, "PAPERBOAT_TOPOLOGY_RELAY_PORT=" + relayPort, "PAPERBOAT_TOPOLOGY_DATABASE_DSN=postgres://postgres:postgres@postgres:5432/paperboat?sslmode=disable"}
		if topology.cancellation {
			authorityEnvironment = append(authorityEnvironment, "PAPERBOAT_TOPOLOGY_AUTHORITY_CANCELLATION=1")
		}
		if err := scope.RunContainer(ctx, ContainerSpec{Role: "authority", Image: topologyGoImage, Command: []string{"sh", "-c", "while [ ! -x /opt/paperboat-authority-test ]; do sleep 0.05; done; exec /opt/paperboat-authority-test -test.run '^TestTopologyPeerAuthorityProcess$' -test.v"}, Environment: authorityEnvironment, Networks: []string{controlNetwork, "database"}, ExtraHosts: map[string]string{"postgres": postgresAddress}, Volumes: []VolumeMount{{Role: "authority", ContainerPath: "/authority"}}, MemoryBytes: 128 << 20, CPUQuota: 40000, PIDs: 96}); err != nil {
			t.Fatal(err)
		}
		if err := scope.UploadExecutable(ctx, "authority", authorityBinary, "/opt/paperboat-authority-test"); err != nil {
			t.Fatal(err)
		}
		authorityAddress, err = scope.ContainerAddress("authority", controlNetwork)
		if err != nil {
			t.Fatal(err)
		}
	}
	waitForMarker := func(role, marker string) {
		t.Helper()
		markerTimeout := 15 * time.Second
		if topology.sshWorkflow {
			markerTimeout = 75 * time.Second
		}
		deadline := time.Now().Add(markerTimeout)
		for time.Now().Before(deadline) {
			logs, err := scope.Logs(ctx, role, 64<<10)
			if err == nil && bytes.Contains(logs.Stdout, []byte(marker)) {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		logs := make(map[string]ContainerLogs, 4)
		for _, diagnosticRole := range []string{"edge", "authority", "client", "host"} {
			logs[diagnosticRole], _ = scope.Logs(ctx, diagnosticRole, 64<<10)
		}
		t.Fatalf("%s missing marker %q: edge=%q authority=%q client=%q host=%q", role, marker, logs["edge"].Stdout, logs["authority"].Stdout, logs["client"].Stdout, logs["host"].Stdout)
	}
	waitForMarker("edge", "PAPERBOAT_TOPOLOGY_RELAY_EDGE_READY")
	for _, endpoint := range []struct{ name, role string }{{"client", topology.initiatorRole}, {"host", topology.responderRole}} {
		image := topologyGoImage
		command := "while [ ! -x /opt/paperboat-endpoint-test ]; do sleep 0.05; done; exec /opt/paperboat-endpoint-test -test.run '^TestTopologyEndpointProcess$' -test.v"
		executable := endpointBinary
		executablePath := "/opt/paperboat-endpoint-test"
		processTest := "^TestTopologyEndpointProcess$"
		environment := []string{"PAPERBOAT_TOPOLOGY_ENDPOINT_ROLE=" + endpoint.role, "PAPERBOAT_TOPOLOGY_RELAY_URL=" + topology.url, "PAPERBOAT_TOPOLOGY_RELAY_EXIT_GATE=/tmp/paperboat-relay-exit"}
		var volumes []VolumeMount
		if topology.hostService {
			volumes = []VolumeMount{{Role: "authority", ContainerPath: "/authority"}}
		}
		if topology.hostService && endpoint.name == "host" {
			command = "while [ ! -x /opt/paperboat-host-test ] || [ ! -e /tmp/paperboat-endpoint-start ]; do sleep 0.05; done; exec /opt/paperboat-host-test -test.run '^TestTopologyHostServiceProcess$' -test.v"
			executable = hostBinary
			executablePath = "/opt/paperboat-host-test"
			processTest = "^TestTopologyHostServiceProcess$"
			environment = []string{"PAPERBOAT_TOPOLOGY_HOST_ROLE=" + endpoint.role, "PAPERBOAT_TOPOLOGY_RELAY_URL=" + topology.url, "PAPERBOAT_TOPOLOGY_RELAY_EXIT_GATE=/tmp/paperboat-relay-exit"}
		}
		if topology.terminalPing && endpoint.name == "client" {
			command = "while [ ! -x /opt/paperboat-terminal-test ] || [ ! -e /tmp/paperboat-endpoint-start ]; do sleep 0.05; done; exec /opt/paperboat-terminal-test -test.run '^TestTopologyPeerTerminalPingProcess$' -test.v"
			executable = terminalBinary
			executablePath = "/opt/paperboat-terminal-test"
			processTest = "^TestTopologyPeerTerminalPingProcess$"
			environment = []string{"PAPERBOAT_TOPOLOGY_TERMINAL_ROLE=" + endpoint.role}
		}
		if topology.sshWorkflow {
			startGate := ""
			if topology.blockUDP {
				startGate = " || [ ! -e /tmp/paperboat-endpoint-start ]"
			}
			command = "while [ ! -x " + executablePath + " ] || [ ! -e /tmp/paperboat-rsync-ready ]" + startGate + "; do sleep 0.05; done; exec " + executablePath + " -test.run '" + processTest + "' -test.v"
		}
		if topology.blockUDP || topology.sshWorkflow || topology.hostService && endpoint.name == "host" {
			image = topologyNetToolsImage
		}
		if topology.blockUDP {
			if (!topology.hostService || endpoint.name != "host") && (!topology.terminalPing || endpoint.name != "client") {
				command = "while [ ! -x /opt/paperboat-endpoint-test ] || [ ! -e /tmp/paperboat-endpoint-start ]; do sleep 0.05; done; exec /opt/paperboat-endpoint-test -test.run '^TestTopologyEndpointProcess$' -test.v"
			}
		}
		edgeAddress := clientEdgeAddress
		networks := clientNetworks
		if endpoint.name == "host" {
			edgeAddress = hostEdgeAddress
			networks = hostNetworks
		}
		extraHosts := map[string]string{"relay.paperboat.test": edgeAddress}
		if topology.fileRelay && endpoint.name == "client" {
			extraHosts["machine.paperboat.test"] = edgeAddress
		}
		if topology.terminalPing && endpoint.name == "client" {
			extraHosts["authority.paperboat.test"] = authorityAddress
		}
		if err := scope.RunContainer(ctx, ContainerSpec{
			Role: endpoint.name, Image: image,
			Command:     []string{"sh", "-c", command},
			Environment: environment,
			Networks:    networks, ExtraHosts: extraHosts,
			Volumes: volumes, MemoryBytes: 192 << 20, CPUQuota: 50000, PIDs: 96, NetworkAdmin: topology.blockUDP,
		}); err != nil {
			t.Fatal(err)
		}
		if err := scope.UploadExecutable(ctx, endpoint.name, executable, executablePath); err != nil {
			t.Fatal(err)
		}
		for _, packagePath := range rsyncPackages {
			if err := scope.UploadExecutable(ctx, endpoint.name, packagePath, "/tmp/"+filepath.Base(packagePath)); err != nil {
				t.Fatal(err)
			}
		}
		if topology.sshWorkflow {
			if err := scope.Exec(ctx, endpoint.name, []string{"sh", "-c", "set -eu; for package in /tmp/*.apk; do tar -xzf \"$package\" -C /; done; rsync --version | head -1 | grep -Fq 'rsync  version 3.4.1 '; touch /tmp/paperboat-rsync-ready"}); err != nil {
				t.Fatal(err)
			}
		}
	}
	if isolatedRelay {
		assertNoSharedNetwork(t, scope, "client", "host")
		if topology.terminalPing {
			assertNoSharedNetwork(t, scope, "authority", "edge")
			assertNoSharedNetwork(t, scope, "postgres", "client")
			assertNoSharedNetwork(t, scope, "postgres", "host")
		}
	}
	if topology.blockUDP {
		for _, endpoint := range []string{"client", "host"} {
			if err := scope.SetUDPBlocked(endpoint, true); err != nil {
				t.Fatal(err)
			}
			if err := scope.Exec(ctx, endpoint, []string{"touch", "/tmp/paperboat-endpoint-start"}); err != nil {
				t.Fatal(err)
			}
		}
	} else if topology.terminalPing {
		for _, endpoint := range []string{"client", "host"} {
			if err := scope.Exec(ctx, endpoint, []string{"touch", "/tmp/paperboat-endpoint-start"}); err != nil {
				t.Fatal(err)
			}
		}
	}
	endpoints := []struct{ name, marker string }{{"client", topology.initiatorMarker}, {"host", topology.responderMarker}}
	for _, endpoint := range endpoints {
		waitForMarker(endpoint.name, endpoint.marker)
	}
	if topology.fileRelay {
		logs, err := scope.Logs(ctx, "edge", 64<<10)
		if err != nil {
			t.Fatal(err)
		}
		expected := []byte("PAPERBOAT_TOPOLOGY_FILE_RELAY proto=" + topology.fileCarrier + " ")
		relayEvidence := topology.terminalCarrier == "direct-quic" || bytes.Contains(logs.Stdout, []byte("PAPERBOAT_TOPOLOGY_RELAY_ADMITTED role=1 carrier=2")) && bytes.Contains(logs.Stdout, []byte("PAPERBOAT_TOPOLOGY_RELAY_ADMITTED role=2 carrier=2"))
		if !bytes.Contains(logs.Stdout, expected) || !bytes.Contains(logs.Stdout, []byte("path=/v1/file-transfers")) || !relayEvidence {
			t.Fatalf("file relay carrier/key-control evidence is incomplete: stdout=%q", logs.Stdout)
		}
		unexpected := "HTTP/2.0"
		if topology.fileCarrier == unexpected {
			unexpected = "HTTP/3.0"
		}
		for _, line := range bytes.Split(logs.Stdout, []byte{'\n'}) {
			if bytes.Contains(line, []byte("PAPERBOAT_TOPOLOGY_FILE_RELAY")) && bytes.Contains(line, []byte("path=/v1/file-transfers")) && bytes.Contains(line, []byte("proto="+unexpected)) {
				t.Fatalf("file resource used unexpected carrier: %q", line)
			}
		}
		if topology.reverseFileWorkflow && topology.terminalCarrier == "direct-quic" {
			for _, forbidden := range []string{"/e2ee-manifest", "/chunks/", "/receipt"} {
				if bytes.Contains(logs.Stdout, []byte(forbidden)) {
					t.Fatalf("reverse direct resource bytes reached the HTTP edge (%s): stdout=%q", forbidden, logs.Stdout)
				}
			}
			if !bytes.Contains(logs.Stdout, []byte("path=/v1/file-transfers/pending")) {
				t.Fatalf("reverse direct discovery did not use opaque pending metadata: stdout=%q", logs.Stdout)
			}
		}
	}
	if topology.forbidRelay {
		logs, err := scope.Logs(ctx, "edge", 64<<10)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(logs.Stdout, []byte("PAPERBOAT_TOPOLOGY_RELAY_ADMITTED")) {
			t.Fatalf("direct-only workflow admitted a relay leg: stdout=%q", logs.Stdout)
		}
	}
	if topology.terminalPing {
		waitForMarker("authority", "PAPERBOAT_TOPOLOGY_AUTHORITY_OK")
		if exit, err := scope.Wait(ctx, "authority"); err != nil || exit != 0 {
			logs, _ := scope.Logs(ctx, "authority", 64<<10)
			t.Fatalf("authority exit=%d error=%v logs=%+v", exit, err, logs)
		}
	}
	for _, endpoint := range endpoints {
		if err := scope.Exec(ctx, endpoint.name, []string{"touch", "/tmp/paperboat-relay-exit"}); err != nil {
			t.Fatal(err)
		}
	}
	for _, endpoint := range endpoints {
		exit, err := scope.Wait(ctx, endpoint.name)
		if err != nil || exit != 0 {
			logs := make(map[string]ContainerLogs, 3)
			for _, role := range []string{"edge", "client", "host"} {
				logs[role], _ = scope.Logs(ctx, role, 64<<10)
			}
			t.Fatalf("%s exit=%d error=%v logs=%+v", endpoint.name, exit, err, logs)
		}
	}
	if _, err := scope.Sample(ctx, "edge"); err != nil {
		t.Fatal(err)
	}
	report, err := scope.Close(true)
	if err != nil {
		t.Fatal(err)
	}
	closed = true
	wantVolumes := 0
	if topology.hostService {
		wantVolumes = 1
	}
	wantContainers := 3
	wantNetworks := 1
	if isolatedRelay {
		wantNetworks = 2
	}
	if topology.terminalPing {
		wantContainers, wantVolumes = 5, 1
		if isolatedRelay {
			wantNetworks = 4
		} else {
			wantNetworks = 2
		}
	}
	if report.RemovedContainers != wantContainers || report.RemovedNetworks != wantNetworks || report.RemovedVolumes != wantVolumes {
		t.Fatalf("cleanup=%+v", report)
	}
}

func fetchTopologyRsyncPackages(t *testing.T, ctx context.Context) []string {
	t.Helper()
	client := &http.Client{Timeout: 15 * time.Second}
	directory := t.TempDir()
	paths := make([]string, 0, len(topologyRsyncPackages))
	for _, artifact := range topologyRsyncPackages {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, topologyAlpinePackageBaseURL+artifact.name, nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatalf("fetch pinned topology package %s: %v", artifact.name, err)
		}
		content, readErr := io.ReadAll(io.LimitReader(response.Body, 2<<20))
		closeErr := response.Body.Close()
		if response.StatusCode != http.StatusOK || readErr != nil || closeErr != nil || len(content) == 0 || len(content) == 2<<20 {
			t.Fatalf("fetch pinned topology package %s: status=%d bytes=%d: %v", artifact.name, response.StatusCode, len(content), errors.Join(readErr, closeErr))
		}
		digest := fmt.Sprintf("%x", sha256.Sum256(content))
		if digest != artifact.sha256 {
			t.Fatalf("pinned topology package %s digest=%s", artifact.name, digest)
		}
		path := filepath.Join(directory, artifact.name)
		if err := os.WriteFile(path, content, 0o400); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, path)
	}
	return paths
}

func newIntegrationScope(t *testing.T, ctx context.Context, prefix string) *Scope {
	t.Helper()
	scope, err := New(ctx, Config{NamePrefix: prefix, MaxWait: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

func assertNoSharedNetwork(t *testing.T, scope *Scope, first, second string) {
	t.Helper()
	firstResource, firstOK := scope.containers[first]
	secondResource, secondOK := scope.containers[second]
	if !firstOK || !secondOK || firstResource.Container == nil || secondResource.Container == nil {
		t.Fatalf("cannot inspect topology isolation for %s and %s", first, second)
	}
	for network := range firstResource.Container.NetworkSettings.Networks {
		if _, shared := secondResource.Container.NetworkSettings.Networks[network]; shared {
			t.Fatalf("%s and %s unexpectedly share Docker network %s", first, second, network)
		}
	}
}

func dockerListByRun(runID string) docker.ListContainersOptions {
	return docker.ListContainersOptions{All: true, Filters: map[string][]string{"label": {RunLabel + "=" + runID}}}
}

func mustNetworks(t *testing.T, scope *Scope) []docker.Network {
	t.Helper()
	networks, err := scope.pool.Client.ListNetworks()
	if err != nil {
		t.Fatal(err)
	}
	return networks
}
