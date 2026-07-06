package fly

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Volume struct {
	ID     string
	Name   string
	SizeGB int
	Region string
	State  string
}

type Machine struct {
	ID         string
	Name       string
	State      string
	ImageRef   string
	Region     string
	ConfigHash string
	Tags       map[string]string
}

type MachineSpec struct {
	Name       string
	ImageRef   string
	Region     string
	Size       MachineSize
	VolumeID   string
	MountPath  string
	Env        map[string]string
	Secrets    []MachineSecret
	Command    []string
	ConfigHash string
	Tags       map[string]string
}

type MachineSecret struct {
	EnvVar string
	Name   string
	Value  string
}

type MachineSize struct {
	VCPU     int
	MemoryMB int
}

type Client interface {
	CreateVolume(ctx context.Context, name, region string, sizeGB int, tags map[string]string) (Volume, error)
	GetVolume(ctx context.Context, volumeID string) (Volume, error)
	ListVolumes(ctx context.Context) ([]Volume, error)
	DestroyVolume(ctx context.Context, volumeID string) error
	CreateMachine(ctx context.Context, spec MachineSpec) (Machine, error)
	GetMachine(ctx context.Context, machineID string) (Machine, error)
	UpdateMachine(ctx context.Context, machineID string, spec MachineSpec) (Machine, error)
	StartMachine(ctx context.Context, machineID string) (Machine, error)
	StopMachine(ctx context.Context, machineID string) (Machine, error)
	DestroyMachine(ctx context.Context, machineID string) error
	ListMachines(ctx context.Context, tags map[string]string) ([]Machine, error)
	SetSecret(ctx context.Context, name, value string) error
	DeleteSecret(ctx context.Context, name string) error
}

type HTTPClient struct {
	BaseURL    string
	APIToken   string
	AppName    string
	HTTPClient *http.Client
}

func (c HTTPClient) CreateVolume(ctx context.Context, name, region string, sizeGB int, tags map[string]string) (Volume, error) {
	var out volumeResponse
	err := c.do(ctx, http.MethodPost, fmt.Sprintf("/v1/apps/%s/volumes", c.AppName), volumeCreateRequest{Name: name, Region: region, SizeGB: sizeGB, Encrypted: true}, &out)
	volume := out.volume()
	return volume, err
}

func (c HTTPClient) GetVolume(ctx context.Context, volumeID string) (Volume, error) {
	var out volumeResponse
	err := c.do(ctx, http.MethodGet, fmt.Sprintf("/v1/apps/%s/volumes/%s", c.AppName, volumeID), nil, &out)
	return out.volume(), err
}

func (c HTTPClient) ListVolumes(ctx context.Context) ([]Volume, error) {
	var out []volumeResponse
	if err := c.do(ctx, http.MethodGet, fmt.Sprintf("/v1/apps/%s/volumes", c.AppName), nil, &out); err != nil {
		return nil, err
	}
	volumes := make([]Volume, 0, len(out))
	for _, volume := range out {
		volumes = append(volumes, volume.volume())
	}
	return volumes, nil
}

func (c HTTPClient) DestroyVolume(ctx context.Context, volumeID string) error {
	return c.do(ctx, http.MethodDelete, fmt.Sprintf("/v1/apps/%s/volumes/%s", c.AppName, volumeID), nil, nil)
}

func (c HTTPClient) CreateMachine(ctx context.Context, spec MachineSpec) (Machine, error) {
	if err := c.setSpecSecrets(ctx, spec); err != nil {
		return Machine{}, err
	}
	var out machineResponse
	err := c.do(ctx, http.MethodPost, fmt.Sprintf("/v1/apps/%s/machines", c.AppName), machineCreateRequestFromSpec(spec), &out)
	return out.machine(), err
}

func (c HTTPClient) GetMachine(ctx context.Context, machineID string) (Machine, error) {
	var out machineResponse
	err := c.do(ctx, http.MethodGet, fmt.Sprintf("/v1/apps/%s/machines/%s", c.AppName, machineID), nil, &out)
	return out.machine(), err
}

func (c HTTPClient) UpdateMachine(ctx context.Context, machineID string, spec MachineSpec) (Machine, error) {
	if err := c.setSpecSecrets(ctx, spec); err != nil {
		return Machine{}, err
	}
	var out machineResponse
	err := c.do(ctx, http.MethodPost, fmt.Sprintf("/v1/apps/%s/machines/%s", c.AppName, machineID), machineUpdateRequestFromSpec(spec), &out)
	return out.machine(), err
}

func (c HTTPClient) StartMachine(ctx context.Context, machineID string) (Machine, error) {
	var out machineResponse
	err := c.do(ctx, http.MethodPost, fmt.Sprintf("/v1/apps/%s/machines/%s/start", c.AppName, machineID), nil, &out)
	return out.machine(), err
}

func (c HTTPClient) StopMachine(ctx context.Context, machineID string) (Machine, error) {
	var out machineResponse
	err := c.do(ctx, http.MethodPost, fmt.Sprintf("/v1/apps/%s/machines/%s/stop", c.AppName, machineID), nil, &out)
	return out.machine(), err
}

func (c HTTPClient) DestroyMachine(ctx context.Context, machineID string) error {
	return c.do(ctx, http.MethodDelete, fmt.Sprintf("/v1/apps/%s/machines/%s", c.AppName, machineID), nil, nil)
}

func (c HTTPClient) ListMachines(ctx context.Context, tags map[string]string) ([]Machine, error) {
	var out []machineResponse
	if err := c.do(ctx, http.MethodGet, fmt.Sprintf("/v1/apps/%s/machines", c.AppName), nil, &out); err != nil {
		return nil, err
	}
	machines := make([]Machine, 0, len(out))
	for _, machine := range out {
		machines = append(machines, machine.machine())
	}
	return machines, nil
}

func (c HTTPClient) SetSecret(ctx context.Context, name, value string) error {
	return c.do(ctx, http.MethodPost, fmt.Sprintf("/v1/apps/%s/secrets/%s", c.AppName, name), secretSetRequest{Value: value}, nil)
}

func (c HTTPClient) DeleteSecret(ctx context.Context, name string) error {
	return c.do(ctx, http.MethodDelete, fmt.Sprintf("/v1/apps/%s/secrets/%s", c.AppName, name), nil, nil)
}

func (c HTTPClient) setSpecSecrets(ctx context.Context, spec MachineSpec) error {
	for _, secret := range spec.Secrets {
		if secret.Name == "" || secret.Value == "" {
			continue
		}
		if err := c.SetSecret(ctx, secret.Name, secret.Value); err != nil {
			return err
		}
	}
	return nil
}

func (c HTTPClient) do(ctx context.Context, method, path string, body any, out any) error {
	base := strings.TrimRight(c.BaseURL, "/")
	if base == "" {
		base = "https://api.machines.dev"
	}
	var reader io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, base+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.APIToken)
	req.Header.Set("Content-Type", "application/json")
	client := c.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if resp.StatusCode == http.StatusNotFound {
			return ErrNotFound
		}
		return fmt.Errorf("fly api returned %s", resp.Status)
	}
	if out == nil || resp.StatusCode == http.StatusNoContent {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

type volumeCreateRequest struct {
	Name      string `json:"name"`
	Region    string `json:"region"`
	SizeGB    int    `json:"size_gb"`
	Encrypted bool   `json:"encrypted"`
}

type volumeResponse struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	SizeGB int    `json:"size_gb"`
	Region string `json:"region"`
	State  string `json:"state"`
}

func (v volumeResponse) volume() Volume {
	return Volume{ID: v.ID, Name: v.Name, SizeGB: v.SizeGB, Region: v.Region, State: v.State}
}

type machineCreateRequest struct {
	Name   string        `json:"name"`
	Region string        `json:"region"`
	Config machineConfig `json:"config"`
}

type machineUpdateRequest struct {
	Config machineConfig `json:"config"`
}

type machineConfig struct {
	Image    string            `json:"image"`
	Env      map[string]string `json:"env,omitempty"`
	Guest    machineGuest      `json:"guest"`
	Init     machineInit       `json:"init,omitempty"`
	Mounts   []machineMount    `json:"mounts,omitempty"`
	Secrets  []machineSecret   `json:"secrets,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

type machineGuest struct {
	CPUs     int `json:"cpus"`
	MemoryMB int `json:"memory_mb"`
}

type machineInit struct {
	Cmd []string `json:"cmd,omitempty"`
}

type machineMount struct {
	Volume string `json:"volume"`
	Path   string `json:"path"`
}

type machineSecret struct {
	EnvVar string `json:"env_var"`
	Name   string `json:"name,omitempty"`
}

type secretSetRequest struct {
	Value string `json:"value"`
}

type machineResponse struct {
	ID     string        `json:"id"`
	Name   string        `json:"name"`
	State  string        `json:"state"`
	Region string        `json:"region"`
	Config machineConfig `json:"config"`
}

func machineCreateRequestFromSpec(spec MachineSpec) machineCreateRequest {
	return machineCreateRequest{Name: spec.Name, Region: spec.Region, Config: machineConfigFromSpec(spec)}
}

func machineUpdateRequestFromSpec(spec MachineSpec) machineUpdateRequest {
	return machineUpdateRequest{Config: machineConfigFromSpec(spec)}
}

func machineConfigFromSpec(spec MachineSpec) machineConfig {
	env := cloneMap(spec.Env)
	if env == nil {
		env = map[string]string{}
	}
	metadata := cloneMap(spec.Tags)
	if metadata == nil {
		metadata = map[string]string{}
	}
	if spec.ConfigHash != "" {
		metadata["paperboat_config_hash"] = spec.ConfigHash
	}
	cfg := machineConfig{
		Image:    spec.ImageRef,
		Env:      env,
		Guest:    machineGuest{CPUs: spec.Size.VCPU, MemoryMB: spec.Size.MemoryMB},
		Metadata: metadata,
	}
	for _, secret := range spec.Secrets {
		if secret.EnvVar == "" || secret.Name == "" {
			continue
		}
		cfg.Secrets = append(cfg.Secrets, machineSecret{EnvVar: secret.EnvVar, Name: secret.Name})
	}
	if len(spec.Command) > 0 {
		cfg.Init = machineInit{Cmd: append([]string(nil), spec.Command...)}
	}
	if spec.VolumeID != "" && spec.MountPath != "" {
		cfg.Mounts = []machineMount{{Volume: spec.VolumeID, Path: spec.MountPath}}
	}
	return cfg
}

func (m machineResponse) machine() Machine {
	tags := cloneMap(m.Config.Metadata)
	configHash := tags["paperboat_config_hash"]
	return Machine{ID: m.ID, Name: m.Name, State: m.State, ImageRef: m.Config.Image, Region: m.Region, ConfigHash: configHash, Tags: tags}
}

type FakeClient struct {
	mu           sync.Mutex
	next         int
	Volumes      map[string]Volume
	Machines     map[string]Machine
	MachineSpecs map[string]MachineSpec
	Calls        []string
	FailOnce     map[string]error
}

func NewFakeClient() *FakeClient {
	return &FakeClient{Volumes: map[string]Volume{}, Machines: map[string]Machine{}, MachineSpecs: map[string]MachineSpec{}, FailOnce: map[string]error{}}
}

func (f *FakeClient) CreateVolume(ctx context.Context, name, region string, sizeGB int, tags map[string]string) (Volume, error) {
	if err := f.fail("CreateVolume"); err != nil {
		return Volume{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Calls = append(f.Calls, "CreateVolume:"+name)
	for _, volume := range f.Volumes {
		if volume.Name == name {
			return volume, nil
		}
	}
	f.next++
	volume := Volume{ID: fmt.Sprintf("vol_%d", f.next), Name: name, SizeGB: sizeGB, Region: region, State: "created"}
	f.Volumes[volume.ID] = volume
	return volume, nil
}

func (f *FakeClient) GetVolume(ctx context.Context, volumeID string) (Volume, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	volume, ok := f.Volumes[volumeID]
	if !ok {
		return Volume{}, ErrNotFound
	}
	return volume, nil
}

func (f *FakeClient) ListVolumes(ctx context.Context) ([]Volume, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []Volume
	for _, volume := range f.Volumes {
		out = append(out, volume)
	}
	return out, nil
}

func (f *FakeClient) DestroyVolume(ctx context.Context, volumeID string) error {
	if err := f.fail("DestroyVolume"); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Calls = append(f.Calls, "DestroyVolume:"+volumeID)
	delete(f.Volumes, volumeID)
	return nil
}

func (f *FakeClient) CreateMachine(ctx context.Context, spec MachineSpec) (Machine, error) {
	if err := f.fail("CreateMachine"); err != nil {
		return Machine{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Calls = append(f.Calls, "CreateMachine:"+spec.Name)
	for _, machine := range f.Machines {
		if machine.Name == spec.Name {
			return machine, nil
		}
	}
	f.next++
	machine := Machine{ID: fmt.Sprintf("mach_%d", f.next), Name: spec.Name, State: "stopped", ImageRef: spec.ImageRef, Region: spec.Region, ConfigHash: spec.ConfigHash, Tags: cloneMap(spec.Tags)}
	f.Machines[machine.ID] = machine
	f.MachineSpecs[machine.ID] = cloneSpec(spec)
	return machine, nil
}

func (f *FakeClient) GetMachine(ctx context.Context, machineID string) (Machine, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	machine, ok := f.Machines[machineID]
	if !ok {
		return Machine{}, ErrNotFound
	}
	return machine, nil
}

func (f *FakeClient) UpdateMachine(ctx context.Context, machineID string, spec MachineSpec) (Machine, error) {
	if err := f.fail("UpdateMachine"); err != nil {
		return Machine{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Calls = append(f.Calls, "UpdateMachine:"+machineID)
	machine, ok := f.Machines[machineID]
	if !ok {
		return Machine{}, ErrNotFound
	}
	machine.ImageRef = spec.ImageRef
	machine.Region = spec.Region
	machine.ConfigHash = spec.ConfigHash
	machine.Tags = cloneMap(spec.Tags)
	f.Machines[machineID] = machine
	f.MachineSpecs[machineID] = cloneSpec(spec)
	return machine, nil
}

func (f *FakeClient) SetSecret(ctx context.Context, name, value string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Calls = append(f.Calls, "SetSecret:"+name)
	return nil
}

func (f *FakeClient) DeleteSecret(ctx context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Calls = append(f.Calls, "DeleteSecret:"+name)
	return nil
}

func (f *FakeClient) StartMachine(ctx context.Context, machineID string) (Machine, error) {
	return f.setMachineState("StartMachine", machineID, "running")
}

func (f *FakeClient) StopMachine(ctx context.Context, machineID string) (Machine, error) {
	return f.setMachineState("StopMachine", machineID, "stopped")
}

func (f *FakeClient) DestroyMachine(ctx context.Context, machineID string) error {
	if err := f.fail("DestroyMachine"); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Calls = append(f.Calls, "DestroyMachine:"+machineID)
	delete(f.Machines, machineID)
	delete(f.MachineSpecs, machineID)
	return nil
}

func (f *FakeClient) ListMachines(ctx context.Context, tags map[string]string) ([]Machine, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []Machine
	for _, machine := range f.Machines {
		out = append(out, machine)
	}
	return out, nil
}

func (f *FakeClient) setMachineState(call, machineID, state string) (Machine, error) {
	if err := f.fail(call); err != nil {
		return Machine{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Calls = append(f.Calls, call+":"+machineID)
	machine, ok := f.Machines[machineID]
	if !ok {
		return Machine{}, ErrNotFound
	}
	machine.State = state
	f.Machines[machineID] = machine
	return machine, nil
}

func (f *FakeClient) fail(call string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.FailOnce == nil {
		return nil
	}
	err := f.FailOnce[call]
	if err != nil {
		delete(f.FailOnce, call)
	}
	return err
}

var ErrNotFound = errors.New("fly resource not found")

func cloneMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func cloneSpec(spec MachineSpec) MachineSpec {
	spec.Env = cloneMap(spec.Env)
	spec.Secrets = append([]MachineSecret(nil), spec.Secrets...)
	spec.Tags = cloneMap(spec.Tags)
	spec.Command = append([]string(nil), spec.Command...)
	return spec
}
