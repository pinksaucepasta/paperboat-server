package fly

import (
	"context"
	"errors"
	"fmt"
	"sync"
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
