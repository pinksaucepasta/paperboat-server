//go:build topology

package testtopology

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ory/dockertest/v3"
	docker "github.com/ory/dockertest/v3/docker"
)

const (
	RunLabel       = "paperboat.test.run"
	RoleLabel      = "paperboat.test.role"
	maxEvents      = 512
	maxUploadBytes = 128 << 20
)

var (
	ErrInvalid       = errors.New("test topology configuration is invalid")
	ErrUnknown       = errors.New("test topology resource is unknown")
	ErrOwnership     = errors.New("test topology resource ownership changed")
	ErrClosed        = errors.New("test topology is closed")
	ErrCommand       = errors.New("test topology container command failed")
	rolePattern      = regexp.MustCompile(`^[a-z][a-z0-9-]{0,47}$`)
	digestHexPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
	portPattern      = regexp.MustCompile(`^[1-9][0-9]{0,4}/(tcp|udp)$`)
)

type Config struct {
	DockerEndpoint    string
	NamePrefix        string
	PreserveOnFailure bool
	MaxWait           time.Duration
}

type ContainerSpec struct {
	Role         string
	Image        string
	Command      []string
	Environment  []string
	Networks     []string
	ExtraHosts   map[string]string
	Volumes      []VolumeMount
	PublishPorts []string
	MemoryBytes  int64
	CPUQuota     int64
	PIDs         int64
	NetworkAdmin bool
	ReadOnlyRoot bool
}

type VolumeMount struct {
	Role          string
	ContainerPath string
	ReadOnly      bool
}

type ContainerLogs struct {
	Stdout    []byte `json:"stdout"`
	Stderr    []byte `json:"stderr"`
	Truncated bool   `json:"truncated"`
}

type ResourceSample struct {
	Role        string    `json:"role"`
	ObservedAt  time.Time `json:"observed_at"`
	MemoryBytes uint64    `json:"memory_bytes"`
	PIDs        uint64    `json:"pids"`
	CPUUsageNS  uint64    `json:"cpu_usage_ns"`
	NetworkRX   uint64    `json:"network_rx_bytes"`
	NetworkTX   uint64    `json:"network_tx_bytes"`
	BlockRead   uint64    `json:"block_read_bytes"`
	BlockWrite  uint64    `json:"block_write_bytes"`
}

type Event struct {
	Sequence uint64 `json:"sequence"`
	Action   string `json:"action"`
	Role     string `json:"role"`
	Kind     string `json:"kind"`
}

type Evidence struct {
	RunID  string  `json:"run_id"`
	Events []Event `json:"events"`
}

type CleanupReport struct {
	Preserved         bool `json:"preserved"`
	RemovedContainers int  `json:"removed_containers"`
	RemovedNetworks   int  `json:"removed_networks"`
	RemovedVolumes    int  `json:"removed_volumes"`
}

type Scope struct {
	pool              *dockertest.Pool
	runID             string
	prefix            string
	preserveOnFailure bool

	mu         sync.Mutex
	networks   map[string]*dockertest.Network
	containers map[string]*dockertest.Resource
	volumes    map[string]*docker.Volume
	faults     map[string]faultState
	events     []Event
	sequence   uint64
	closed     bool
}

type faultState struct {
	netem      bool
	udpBlocked bool
}

func New(ctx context.Context, config Config) (*Scope, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	prefix := strings.Trim(strings.ToLower(strings.TrimSpace(config.NamePrefix)), "-")
	if !rolePattern.MatchString(prefix) {
		return nil, ErrInvalid
	}
	runID, err := newRunID(prefix)
	if err != nil {
		return nil, err
	}
	pool, err := dockertest.NewPool(strings.TrimSpace(config.DockerEndpoint))
	if err != nil {
		return nil, fmt.Errorf("open Docker pool: %w", err)
	}
	if config.MaxWait > 0 && config.MaxWait <= 10*time.Minute {
		pool.MaxWait = config.MaxWait
	}
	return &Scope{
		pool: pool, runID: runID, prefix: prefix, preserveOnFailure: config.PreserveOnFailure,
		networks: make(map[string]*dockertest.Network), containers: make(map[string]*dockertest.Resource), volumes: make(map[string]*docker.Volume), faults: make(map[string]faultState),
	}, nil
}

func (s *Scope) RunID() string {
	if s == nil {
		return ""
	}
	return s.runID
}

func (s *Scope) CreateNetwork(ctx context.Context, role string, internal bool) error {
	if !validRole(role) {
		return ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	if _, exists := s.networks[role]; exists {
		return ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	network, err := s.pool.CreateNetwork(s.resourceName("network", role), func(options *docker.CreateNetworkOptions) {
		options.Context = ctx
		options.Driver = "bridge"
		options.Internal = internal
		options.CheckDuplicate = true
		options.Labels = s.labels(role)
	})
	if err != nil {
		return fmt.Errorf("create %s network: %w", role, err)
	}
	s.networks[role] = network
	s.recordLocked("create", role, "network")
	return nil
}

func (s *Scope) CreateVolume(ctx context.Context, role string) error {
	if !validRole(role) {
		return ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	if _, exists := s.volumes[role]; exists {
		return ErrInvalid
	}
	volume, err := s.pool.Client.CreateVolume(docker.CreateVolumeOptions{Context: ctx, Name: s.resourceName("volume", role), Labels: s.labels(role)})
	if err != nil {
		return fmt.Errorf("create %s volume: %w", role, err)
	}
	s.volumes[role] = volume
	s.recordLocked("create", role, "volume")
	return nil
}

func (s *Scope) RunContainer(ctx context.Context, spec ContainerSpec) error {
	repository, tag, err := splitDigestImage(spec.Image)
	if err != nil || !validRole(spec.Role) || len(spec.Command) == 0 || spec.MemoryBytes < 16<<20 || spec.MemoryBytes > 8<<30 || spec.CPUQuota < 1 || spec.CPUQuota > 3200000 || spec.PIDs < 8 || spec.PIDs > 4096 {
		return ErrInvalid
	}
	if _, err := s.pool.Client.InspectImage(spec.Image); err != nil {
		if err := s.pool.Client.PullImage(docker.PullImageOptions{Repository: spec.Image, Context: ctx}, docker.AuthConfiguration{}); err != nil {
			return fmt.Errorf("pull pinned image %s: %w", spec.Image, err)
		}
		if _, err := s.pool.Client.InspectImage(spec.Image); err != nil {
			return fmt.Errorf("inspect pinned image %s after pull: %w", spec.Image, err)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	if _, exists := s.containers[spec.Role]; exists {
		return ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	networks := make([]*dockertest.Network, 0, len(spec.Networks))
	seen := make(map[string]struct{}, len(spec.Networks))
	for _, role := range spec.Networks {
		network, exists := s.networks[role]
		if !exists {
			return ErrUnknown
		}
		if _, duplicate := seen[role]; duplicate {
			return ErrInvalid
		}
		seen[role] = struct{}{}
		networks = append(networks, network)
	}
	extraHosts := make([]string, 0, len(spec.ExtraHosts))
	for host, address := range spec.ExtraHosts {
		if !validTestHostname(host) || net.ParseIP(address) == nil {
			return ErrInvalid
		}
		extraHosts = append(extraHosts, host+":"+address)
	}
	slices.Sort(extraHosts)
	mounts := make([]string, 0, len(spec.Volumes))
	seenVolumes := make(map[string]struct{}, len(spec.Volumes))
	for _, mount := range spec.Volumes {
		volume, exists := s.volumes[mount.Role]
		if !exists {
			return ErrUnknown
		}
		if _, duplicate := seenVolumes[mount.Role]; duplicate || !validContainerPath(mount.ContainerPath) {
			return ErrInvalid
		}
		seenVolumes[mount.Role] = struct{}{}
		value := volume.Name + ":" + mount.ContainerPath
		if mount.ReadOnly {
			value += ":ro"
		}
		mounts = append(mounts, value)
	}
	exposedPorts := make([]string, 0, len(spec.PublishPorts))
	portBindings := make(map[docker.Port][]docker.PortBinding, len(spec.PublishPorts))
	seenPorts := make(map[string]struct{}, len(spec.PublishPorts))
	for _, port := range spec.PublishPorts {
		if !validPort(port) {
			return ErrInvalid
		}
		if _, duplicate := seenPorts[port]; duplicate {
			return ErrInvalid
		}
		seenPorts[port] = struct{}{}
		exposedPorts = append(exposedPorts, port)
		hostPort, err := reserveLoopbackPort()
		if err != nil {
			return fmt.Errorf("reserve host port for %s: %w", port, err)
		}
		portBindings[docker.Port(port)] = []docker.PortBinding{{HostIP: "127.0.0.1", HostPort: hostPort}}
	}
	capabilities := []string(nil)
	if spec.NetworkAdmin {
		capabilities = []string{"NET_ADMIN"}
	}
	resource, err := s.pool.RunWithOptions(&dockertest.RunOptions{
		Name: s.resourceName("container", spec.Role), Repository: repository, Tag: tag,
		Cmd: slices.Clone(spec.Command), Env: slices.Clone(spec.Environment), Networks: networks, Mounts: mounts, ExtraHosts: extraHosts,
		ExposedPorts: exposedPorts, PortBindings: portBindings,
		Labels: s.labels(spec.Role), CapAdd: capabilities,
	}, func(host *docker.HostConfig) {
		host.Memory = spec.MemoryBytes
		host.MemorySwap = spec.MemoryBytes
		host.CPUPeriod = 100000
		host.CPUQuota = spec.CPUQuota
		host.PidsLimit = spec.PIDs
		host.ReadonlyRootfs = spec.ReadOnlyRoot
		host.RestartPolicy = docker.RestartPolicy{Name: "no"}
		host.PublishAllPorts = len(exposedPorts) > 0
		host.PortBindings = portBindings
	})
	if err != nil {
		return fmt.Errorf("start %s container: %w", spec.Role, err)
	}
	s.containers[spec.Role] = resource
	s.recordLocked("create", spec.Role, "container")
	return nil
}

func (s *Scope) HostPort(role, containerPort string) (string, error) {
	if !validRole(role) || !validPort(containerPort) {
		return "", ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return "", ErrClosed
	}
	resource, exists := s.containers[role]
	if !exists {
		return "", ErrUnknown
	}
	inspected, err := s.pool.Client.InspectContainer(resource.Container.ID)
	if err != nil {
		return "", err
	}
	if inspected.Config == nil || inspected.Config.Labels[RunLabel] != s.runID {
		return "", ErrOwnership
	}
	resource.Container = inspected
	if inspected.NetworkSettings == nil {
		return "", ErrUnknown
	}
	bindings := inspected.NetworkSettings.Ports[docker.Port(containerPort)]
	if len(bindings) != 1 || bindings[0].HostIP != "127.0.0.1" || bindings[0].HostPort == "" {
		return "", fmt.Errorf("%w: %s bindings=%#v configured=%#v exposed=%#v", ErrUnknown, containerPort, bindings, inspected.HostConfig.PortBindings, inspected.Config.ExposedPorts)
	}
	return "127.0.0.1:" + bindings[0].HostPort, nil
}

func (s *Scope) ContainerAddress(role, networkRole string) (string, error) {
	if !validRole(role) || !validRole(networkRole) {
		return "", ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return "", ErrClosed
	}
	resource, containerExists := s.containers[role]
	network, networkExists := s.networks[networkRole]
	if !containerExists || !networkExists {
		return "", ErrUnknown
	}
	inspected, err := s.pool.Client.InspectContainer(resource.Container.ID)
	if err != nil {
		return "", err
	}
	if inspected.Config == nil || inspected.Config.Labels[RunLabel] != s.runID || inspected.NetworkSettings == nil {
		return "", ErrOwnership
	}
	var address string
	for _, endpoint := range inspected.NetworkSettings.Networks {
		if endpoint.NetworkID == network.Network.ID {
			address = endpoint.IPAddress
			break
		}
	}
	if net.ParseIP(address) == nil {
		return "", ErrUnknown
	}
	resource.Container = inspected
	return address, nil
}

func (s *Scope) UploadExecutable(ctx context.Context, role, sourcePath, targetPath string) error {
	if !validRole(role) || !validContainerPath(targetPath) || path.Base(targetPath) == "." || path.Base(targetPath) == "/" {
		return ErrInvalid
	}
	file, err := os.Open(sourcePath)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maxUploadBytes {
		return ErrInvalid
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrClosed
	}
	resource, exists := s.containers[role]
	if !exists {
		s.mu.Unlock()
		return ErrUnknown
	}
	inspected, err := s.pool.Client.InspectContainer(resource.Container.ID)
	if err != nil || inspected.Config == nil || inspected.Config.Labels[RunLabel] != s.runID {
		s.mu.Unlock()
		if err != nil {
			return err
		}
		return ErrOwnership
	}
	containerID := resource.Container.ID
	s.mu.Unlock()
	var archive bytes.Buffer
	writer := tar.NewWriter(&archive)
	temporaryName := "." + path.Base(targetPath) + ".paperboat-upload"
	header := &tar.Header{Name: temporaryName, Mode: 0o500, Size: info.Size(), ModTime: time.Unix(0, 0)}
	if err := writer.WriteHeader(header); err != nil {
		return err
	}
	if _, err := io.Copy(writer, file); err != nil {
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}
	if err := s.pool.Client.UploadToContainer(containerID, docker.UploadToContainerOptions{Context: ctx, InputStream: &archive, Path: path.Dir(targetPath), NoOverwriteDirNonDir: true}); err != nil {
		return err
	}
	var stdout, stderr bytes.Buffer
	if code, err := resource.Exec([]string{"mv", path.Join(path.Dir(targetPath), temporaryName), targetPath}, dockertest.ExecOptions{StdOut: &stdout, StdErr: &stderr}); err != nil || code != 0 {
		return fmt.Errorf("activate uploaded executable: exit=%d err=%v stdout=%q stderr=%q", code, err, stdout.String(), stderr.String())
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		s.recordLocked("upload", role, "executable")
	}
	return nil
}

func (s *Scope) Wait(ctx context.Context, role string) (int, error) {
	if !validRole(role) {
		return 0, ErrInvalid
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return 0, ErrClosed
	}
	resource, exists := s.containers[role]
	if !exists {
		s.mu.Unlock()
		return 0, ErrUnknown
	}
	containerID := resource.Container.ID
	s.mu.Unlock()
	return s.pool.Client.WaitContainerWithContext(containerID, ctx)
}

func (s *Scope) Exec(ctx context.Context, role string, command []string) error {
	if !validRole(role) || len(command) == 0 || len(command) > 64 || ctx == nil {
		return ErrInvalid
	}
	total := 0
	for _, argument := range command {
		total += len(argument)
		if argument == "" || total > 16<<10 || strings.ContainsRune(argument, 0) {
			return ErrInvalid
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	resource, exists := s.containers[role]
	if !exists {
		return ErrUnknown
	}
	if code, err := resource.Exec(slices.Clone(command), dockertest.ExecOptions{}); err != nil || code != 0 {
		return fmt.Errorf("exec in %s: exit=%d: %w", role, code, errors.Join(ErrCommand, err))
	}
	s.recordLocked("exec", role, "container")
	return nil
}

func (s *Scope) Logs(ctx context.Context, role string, maximumBytes int) (ContainerLogs, error) {
	if !validRole(role) || maximumBytes < 1 || maximumBytes > 16<<20 {
		return ContainerLogs{}, ErrInvalid
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ContainerLogs{}, ErrClosed
	}
	resource, exists := s.containers[role]
	containerID := ""
	if exists {
		containerID = resource.Container.ID
	}
	s.mu.Unlock()
	if !exists {
		return ContainerLogs{}, ErrUnknown
	}
	stdout, stderr := newBoundedBuffer(maximumBytes), newBoundedBuffer(maximumBytes)
	err := s.pool.Client.Logs(docker.LogsOptions{Context: ctx, Container: containerID, OutputStream: stdout, ErrorStream: stderr, Tail: "all", Stdout: true, Stderr: true})
	return ContainerLogs{Stdout: stdout.Bytes(), Stderr: stderr.Bytes(), Truncated: stdout.truncated || stderr.truncated}, err
}

func (s *Scope) Sample(ctx context.Context, role string) (ResourceSample, error) {
	if !validRole(role) {
		return ResourceSample{}, ErrInvalid
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ResourceSample{}, ErrClosed
	}
	resource, exists := s.containers[role]
	containerID := ""
	if exists {
		containerID = resource.Container.ID
	}
	s.mu.Unlock()
	if !exists {
		return ResourceSample{}, ErrUnknown
	}
	stats := make(chan *docker.Stats, 1)
	if err := s.pool.Client.Stats(docker.StatsOptions{ID: containerID, Stats: stats, Stream: false, Context: ctx, Timeout: 5 * time.Second}); err != nil {
		return ResourceSample{}, err
	}
	value, ok := <-stats
	if !ok || value == nil {
		return ResourceSample{}, ErrUnknown
	}
	sample := ResourceSample{Role: role, ObservedAt: value.Read, MemoryBytes: value.MemoryStats.Usage, PIDs: value.PidsStats.Current, CPUUsageNS: value.CPUStats.CPUUsage.TotalUsage}
	for _, network := range value.Networks {
		sample.NetworkRX += network.RxBytes
		sample.NetworkTX += network.TxBytes
	}
	for _, entry := range value.BlkioStats.IOServiceBytesRecursive {
		switch strings.ToLower(entry.Op) {
		case "read":
			sample.BlockRead += entry.Value
		case "write":
			sample.BlockWrite += entry.Value
		}
	}
	return sample, nil
}

func (s *Scope) Disconnect(ctx context.Context, containerRole, networkRole string) error {
	return s.changeConnection(ctx, containerRole, networkRole, false)
}

func (s *Scope) Reconnect(ctx context.Context, containerRole, networkRole string) error {
	return s.changeConnection(ctx, containerRole, networkRole, true)
}

func (s *Scope) changeConnection(ctx context.Context, containerRole, networkRole string, connect bool) error {
	if !validRole(containerRole) || !validRole(networkRole) {
		return ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	resource, resourceExists := s.containers[containerRole]
	network, networkExists := s.networks[networkRole]
	if !resourceExists || !networkExists {
		return ErrUnknown
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	var err error
	if connect {
		err = resource.ConnectToNetwork(network)
	} else {
		err = resource.DisconnectFromNetwork(network)
	}
	if err != nil {
		return err
	}
	action := "disconnect"
	if connect {
		action = "reconnect"
	}
	s.recordLocked(action, containerRole, "network")
	return nil
}

func (s *Scope) Restart(ctx context.Context, role string, timeout time.Duration) error {
	if !validRole(role) || timeout < 0 || timeout > time.Minute {
		return ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	resource, exists := s.containers[role]
	if !exists {
		return ErrUnknown
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.pool.Client.RestartContainer(resource.Container.ID, uint(timeout.Seconds())); err != nil {
		return err
	}
	inspected, err := s.pool.Client.InspectContainerWithContext(resource.Container.ID, ctx)
	if err != nil {
		return err
	}
	resource.Container = inspected
	s.recordLocked("restart", role, "container")
	return nil
}

func (s *Scope) SetNetworkImpairment(role string, latency time.Duration, lossPercent float64) error {
	if !validRole(role) || latency < 0 || latency > 5*time.Second || lossPercent < 0 || lossPercent > 100 {
		return ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	resource, exists := s.containers[role]
	if !exists {
		return ErrUnknown
	}
	state := s.faults[role]
	if latency == 0 && lossPercent == 0 && !state.netem {
		return nil
	}
	command := []string{"tc", "qdisc", "replace", "dev", "eth0", "root", "netem", "delay", fmt.Sprintf("%dms", latency.Milliseconds()), "loss", fmt.Sprintf("%.3f%%", lossPercent)}
	if latency == 0 && lossPercent == 0 {
		command = []string{"tc", "qdisc", "del", "dev", "eth0", "root"}
	}
	if code, err := resource.Exec(command, dockertest.ExecOptions{}); err != nil || code != 0 {
		return fmt.Errorf("set network impairment: exit=%d: %w", code, err)
	}
	state.netem = latency != 0 || lossPercent != 0
	s.faults[role] = state
	s.recordLocked("network-impairment", role, "fault")
	return nil
}

func (s *Scope) SetUDPBlocked(role string, blocked bool) error {
	if !validRole(role) {
		return ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	resource, exists := s.containers[role]
	if !exists {
		return ErrUnknown
	}
	state := s.faults[role]
	if state.udpBlocked == blocked {
		return nil
	}
	action := "-I"
	if !blocked {
		action = "-D"
	}
	command := []string{"iptables", action, "OUTPUT", "-p", "udp", "-j", "DROP"}
	if code, err := resource.Exec(command, dockertest.ExecOptions{}); err != nil || code != 0 {
		return fmt.Errorf("set UDP block: exit=%d: %w", code, err)
	}
	state.udpBlocked = blocked
	s.faults[role] = state
	s.recordLocked("udp-block", role, "fault")
	return nil
}

func (s *Scope) Evidence() Evidence {
	if s == nil {
		return Evidence{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return Evidence{RunID: s.runID, Events: slices.Clone(s.events)}
}

func (s *Scope) Close(success bool) (CleanupReport, error) {
	if s == nil {
		return CleanupReport{}, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return CleanupReport{}, ErrClosed
	}
	if !success && s.preserveOnFailure {
		s.recordLocked("preserve", "run", "scope")
		return CleanupReport{Preserved: true}, nil
	}
	report := CleanupReport{}
	var cleanupErrors []error
	containerRoles := sortedKeys(s.containers)
	slices.Reverse(containerRoles)
	for _, role := range containerRoles {
		resource := s.containers[role]
		inspected, err := s.pool.Client.InspectContainer(resource.Container.ID)
		if err != nil {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("inspect container %s: %w", role, err))
			continue
		}
		if inspected.Config == nil || inspected.Config.Labels[RunLabel] != s.runID {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("container %s: %w", role, ErrOwnership))
			continue
		}
		resource.Container = inspected
		if err := s.pool.Purge(resource); err != nil {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("remove container %s: %w", role, err))
			continue
		}
		delete(s.containers, role)
		report.RemovedContainers++
		s.recordLocked("remove", role, "container")
	}
	networkRoles := sortedKeys(s.networks)
	slices.Reverse(networkRoles)
	for _, role := range networkRoles {
		network := s.networks[role]
		inspected, err := s.pool.Client.NetworkInfo(network.Network.ID)
		if err != nil {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("inspect network %s: %w", role, err))
			continue
		}
		if inspected.Labels[RunLabel] != s.runID {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("network %s: %w", role, ErrOwnership))
			continue
		}
		network.Network = inspected
		if err := s.pool.RemoveNetwork(network); err != nil {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("remove network %s: %w", role, err))
			continue
		}
		delete(s.networks, role)
		report.RemovedNetworks++
		s.recordLocked("remove", role, "network")
	}
	volumeRoles := sortedKeys(s.volumes)
	slices.Reverse(volumeRoles)
	for _, role := range volumeRoles {
		volume := s.volumes[role]
		inspected, err := s.pool.Client.InspectVolume(volume.Name)
		if err != nil {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("inspect volume %s: %w", role, err))
			continue
		}
		if inspected.Labels[RunLabel] != s.runID {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("volume %s: %w", role, ErrOwnership))
			continue
		}
		if err := s.pool.Client.RemoveVolumeWithOptions(docker.RemoveVolumeOptions{Name: volume.Name}); err != nil {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("remove volume %s: %w", role, err))
			continue
		}
		delete(s.volumes, role)
		report.RemovedVolumes++
		s.recordLocked("remove", role, "volume")
	}
	if len(cleanupErrors) == 0 {
		s.closed = true
	}
	return report, errors.Join(cleanupErrors...)
}

func (s *Scope) labels(role string) map[string]string {
	return map[string]string{RunLabel: s.runID, RoleLabel: role}
}

func (s *Scope) resourceName(kind, role string) string {
	return s.prefix + "-" + s.runID[len(s.prefix)+1:] + "-" + kind + "-" + role
}

func (s *Scope) recordLocked(action, role, kind string) {
	s.sequence++
	event := Event{Sequence: s.sequence, Action: action, Role: role, Kind: kind}
	if len(s.events) == maxEvents {
		copy(s.events, s.events[1:])
		s.events[len(s.events)-1] = event
		return
	}
	s.events = append(s.events, event)
}

func splitDigestImage(image string) (string, string, error) {
	image = strings.TrimSpace(image)
	marker := "@sha256:"
	index := strings.LastIndex(image, marker)
	if index <= 0 {
		return "", "", ErrInvalid
	}
	digest := image[index+len(marker):]
	if !digestHexPattern.MatchString(digest) || strings.ContainsAny(image, " \t\r\n") {
		return "", "", ErrInvalid
	}
	return image[:index+len("@sha256")], digest, nil
}

func newRunID(prefix string) (string, error) {
	var entropy [10]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return "", err
	}
	return prefix + "-" + hex.EncodeToString(entropy[:]), nil
}

func validRole(role string) bool { return rolePattern.MatchString(role) }

func validPort(value string) bool {
	if !portPattern.MatchString(value) {
		return false
	}
	port, err := strconv.ParseUint(strings.SplitN(value, "/", 2)[0], 10, 16)
	return err == nil && port > 0
}

func validContainerPath(value string) bool {
	return strings.HasPrefix(value, "/") && value != "/" && !strings.ContainsAny(value, ":\x00") && !strings.Contains(value, "/../") && !strings.HasSuffix(value, "/..")
}

func validTestHostname(value string) bool {
	if len(value) < 1 || len(value) > 253 || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if !rolePattern.MatchString(label) {
			return false
		}
	}
	return true
}

func reserveLoopbackPort() (string, error) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		return "", err
	}
	return strconv.Itoa(port), nil
}

type boundedBuffer struct {
	buffer    bytes.Buffer
	maximum   int
	truncated bool
}

func newBoundedBuffer(maximum int) *boundedBuffer { return &boundedBuffer{maximum: maximum} }

func (b *boundedBuffer) Write(value []byte) (int, error) {
	original := len(value)
	remaining := b.maximum - b.buffer.Len()
	if remaining < len(value) {
		b.truncated = true
		value = value[:max(remaining, 0)]
	}
	_, _ = b.buffer.Write(value)
	return original, nil
}

func (b *boundedBuffer) Bytes() []byte { return bytes.Clone(b.buffer.Bytes()) }

func sortedKeys[T any](values map[string]T) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}
