package fly

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	flygo "github.com/superfly/fly-go"
	"github.com/superfly/fly-go/flaps"
	"github.com/superfly/fly-go/tokens"
)

type SDKClient struct {
	APIToken string
	AppName  string
	OrgSlug  string
	BaseURL  string

	mu     sync.Mutex
	client *flaps.Client
}

var flapsClientMu sync.Mutex

func (c *SDKClient) ListRegions(ctx context.Context) ([]Region, error) {
	client, err := c.flaps(ctx)
	if err != nil {
		return nil, err
	}
	regions, err := client.GetRegions(ctx)
	if err != nil {
		return nil, mapSDKError(err)
	}
	if regions == nil {
		return nil, nil
	}
	out := make([]Region, 0, len(regions.Regions))
	for _, region := range regions.Regions {
		out = append(out, Region{
			Code:       strings.ToLower(strings.TrimSpace(region.Code)),
			Name:       strings.TrimSpace(region.Name),
			Deprecated: region.Deprecated,
		})
	}
	return out, nil
}

func (c *SDKClient) CreateVolume(ctx context.Context, name, region string, sizeGB int, tags map[string]string) (Volume, error) {
	if err := c.ensureApp(ctx); err != nil {
		return Volume{}, err
	}
	encrypted := true
	created, err := c.flaps(ctx)
	if err != nil {
		return Volume{}, err
	}
	volume, err := created.CreateVolume(ctx, c.AppName, flygo.CreateVolumeRequest{
		Name:      name,
		Region:    region,
		SizeGb:    flygo.IntPointer(sizeGB),
		Encrypted: &encrypted,
	})
	if err != nil {
		return Volume{}, mapSDKError(err)
	}
	return volumeFromSDK(volume), nil
}

func (c *SDKClient) GetVolume(ctx context.Context, volumeID string) (Volume, error) {
	client, err := c.flaps(ctx)
	if err != nil {
		return Volume{}, err
	}
	volume, err := client.GetVolume(ctx, c.AppName, volumeID)
	if err != nil {
		return Volume{}, mapSDKError(err)
	}
	return volumeFromSDK(volume), nil
}

func (c *SDKClient) ListVolumes(ctx context.Context) ([]Volume, error) {
	client, err := c.flaps(ctx)
	if err != nil {
		return nil, err
	}
	volumes, err := client.GetVolumes(ctx, c.AppName)
	if err != nil {
		return nil, mapSDKError(err)
	}
	out := make([]Volume, 0, len(volumes))
	for _, volume := range volumes {
		volume := volume
		out = append(out, volumeFromSDK(&volume))
	}
	return out, nil
}

func (c *SDKClient) DestroyVolume(ctx context.Context, volumeID string) error {
	client, err := c.flaps(ctx)
	if err != nil {
		return err
	}
	_, err = client.DeleteVolume(ctx, c.AppName, volumeID)
	return mapSDKError(err)
}

func (c *SDKClient) CreateMachine(ctx context.Context, spec MachineSpec) (Machine, error) {
	if err := c.ensureApp(ctx); err != nil {
		return Machine{}, err
	}
	if err := c.setSpecSecrets(ctx, spec); err != nil {
		return Machine{}, err
	}
	client, err := c.flaps(ctx)
	if err != nil {
		return Machine{}, err
	}
	machine, err := client.Launch(ctx, c.AppName, flygo.LaunchMachineInput{
		Name:       spec.Name,
		Region:     spec.Region,
		Config:     sdkMachineConfig(spec),
		SkipLaunch: true,
	})
	if err != nil {
		return Machine{}, mapSDKError(err)
	}
	return machineFromSDK(machine), nil
}

func (c *SDKClient) GetMachine(ctx context.Context, machineID string) (Machine, error) {
	client, err := c.flaps(ctx)
	if err != nil {
		return Machine{}, err
	}
	machine, err := client.Get(ctx, c.AppName, machineID)
	if err != nil {
		return Machine{}, mapSDKError(err)
	}
	return machineFromSDK(machine), nil
}

func (c *SDKClient) UpdateMachine(ctx context.Context, machineID string, spec MachineSpec) (Machine, error) {
	if err := c.setSpecSecrets(ctx, spec); err != nil {
		return Machine{}, err
	}
	client, err := c.flaps(ctx)
	if err != nil {
		return Machine{}, err
	}
	machine, err := client.Update(ctx, c.AppName, flygo.LaunchMachineInput{
		ID:     machineID,
		Name:   spec.Name,
		Region: spec.Region,
		Config: sdkMachineConfig(spec),
	}, "")
	if err != nil {
		return Machine{}, mapSDKError(err)
	}
	return machineFromSDK(machine), nil
}

func (c *SDKClient) StartMachine(ctx context.Context, machineID string) (Machine, error) {
	client, err := c.flaps(ctx)
	if err != nil {
		return Machine{}, err
	}
	if _, err := client.Start(ctx, c.AppName, machineID, ""); err != nil {
		return Machine{}, mapSDKError(err)
	}
	return c.GetMachine(ctx, machineID)
}

func (c *SDKClient) StopMachine(ctx context.Context, machineID string) (Machine, error) {
	client, err := c.flaps(ctx)
	if err != nil {
		return Machine{}, err
	}
	if err := client.Stop(ctx, c.AppName, flygo.StopMachineInput{ID: machineID}, ""); err != nil {
		return Machine{}, mapSDKError(err)
	}
	return c.GetMachine(ctx, machineID)
}

func (c *SDKClient) DestroyMachine(ctx context.Context, machineID string) error {
	client, err := c.flaps(ctx)
	if err != nil {
		return err
	}
	return mapSDKError(client.Destroy(ctx, c.AppName, flygo.RemoveMachineInput{ID: machineID, Kill: true}, ""))
}

func (c *SDKClient) ListMachines(ctx context.Context, tags map[string]string) ([]Machine, error) {
	client, err := c.flaps(ctx)
	if err != nil {
		return nil, err
	}
	machines, err := client.List(ctx, c.AppName, "")
	if err != nil {
		return nil, mapSDKError(err)
	}
	out := make([]Machine, 0, len(machines))
	for _, machine := range machines {
		converted := machineFromSDK(machine)
		if matchesTags(converted.Tags, tags) {
			out = append(out, converted)
		}
	}
	return out, nil
}

func (c *SDKClient) SetSecret(ctx context.Context, name, value string) error {
	client, err := c.flaps(ctx)
	if err != nil {
		return err
	}
	_, err = client.SetAppSecret(ctx, c.AppName, name, value)
	return mapSDKError(err)
}

func (c *SDKClient) DeleteSecret(ctx context.Context, name string) error {
	client, err := c.flaps(ctx)
	if err != nil {
		return err
	}
	_, err = client.DeleteAppSecret(ctx, c.AppName, name)
	return mapSDKError(err)
}

func (c *SDKClient) ensureApp(ctx context.Context) error {
	client, err := c.flaps(ctx)
	if err != nil {
		return err
	}
	if _, err := client.GetApp(ctx, c.AppName); err == nil {
		return nil
	} else if !errors.Is(mapSDKError(err), ErrNotFound) {
		return mapSDKError(err)
	}
	if strings.TrimSpace(c.OrgSlug) == "" {
		return fmt.Errorf("fly org slug is required to create app %q", c.AppName)
	}
	if _, err := client.CreateApp(ctx, flaps.CreateAppRequest{Name: c.AppName, Org: c.OrgSlug}); err != nil {
		if errors.Is(mapSDKError(err), ErrNotFound) {
			return err
		}
		if _, getErr := client.GetApp(ctx, c.AppName); getErr == nil {
			return nil
		}
		return mapSDKError(err)
	}
	return nil
}

func (c *SDKClient) setSpecSecrets(ctx context.Context, spec MachineSpec) error {
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

func (c *SDKClient) flaps(ctx context.Context) (*flaps.Client, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.client != nil {
		return c.client, nil
	}
	flapsClientMu.Lock()
	defer flapsClientMu.Unlock()
	restore, err := withFlapsBaseURL(c.BaseURL)
	if err != nil {
		return nil, err
	}
	defer restore()
	client, err := flaps.NewWithOptions(ctx, flaps.NewClientOpts{
		UserAgent: "paperboat-server",
		Tokens:    tokens.Parse(c.APIToken),
	})
	if err != nil {
		return nil, err
	}
	c.client = client
	return client, nil
}

func withFlapsBaseURL(baseURL string) (func(), error) {
	baseURL = strings.TrimSpace(baseURL)
	if baseURL == "" {
		return func() {}, nil
	}
	previous, hadPrevious := os.LookupEnv("FLY_FLAPS_BASE_URL")
	if err := os.Setenv("FLY_FLAPS_BASE_URL", baseURL); err != nil {
		return nil, err
	}
	return func() {
		if hadPrevious {
			_ = os.Setenv("FLY_FLAPS_BASE_URL", previous)
			return
		}
		_ = os.Unsetenv("FLY_FLAPS_BASE_URL")
	}, nil
}

func sdkMachineConfig(spec MachineSpec) *flygo.MachineConfig {
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
	cfg := &flygo.MachineConfig{
		Image:    spec.ImageRef,
		Env:      env,
		Guest:    &flygo.MachineGuest{CPUKind: "shared", CPUs: spec.Size.VCPU, MemoryMB: spec.Size.MemoryMB},
		Metadata: metadata,
	}
	if len(spec.Command) > 0 {
		cfg.Init = flygo.MachineInit{Cmd: append([]string(nil), spec.Command...)}
	}
	if strings.TrimSpace(spec.Hostname) != "" {
		cfg.DNS = &flygo.DNSConfig{Hostname: spec.Hostname}
	}
	if spec.VolumeID != "" && spec.MountPath != "" {
		cfg.Mounts = []flygo.MachineMount{{Volume: spec.VolumeID, Path: spec.MountPath}}
	}
	processSecrets := make([]flygo.MachineSecret, 0, len(spec.Secrets))
	for _, secret := range spec.Secrets {
		if secret.EnvVar == "" || secret.Name == "" {
			continue
		}
		processSecrets = append(processSecrets, flygo.MachineSecret{EnvVar: secret.EnvVar, Name: secret.Name})
	}
	cfg.Processes = []flygo.MachineProcess{{
		Secrets:          processSecrets,
		IgnoreAppSecrets: true,
	}}
	return cfg
}

func volumeFromSDK(volume *flygo.Volume) Volume {
	if volume == nil {
		return Volume{}
	}
	return Volume{ID: volume.ID, Name: volume.Name, SizeGB: volume.SizeGb, Region: volume.Region, State: volume.State}
}

func machineFromSDK(machine *flygo.Machine) Machine {
	if machine == nil {
		return Machine{}
	}
	cfg := machine.GetConfig()
	if cfg == nil {
		cfg = &flygo.MachineConfig{}
	}
	tags := cloneMap(cfg.Metadata)
	configHash := tags["paperboat_config_hash"]
	return Machine{ID: machine.ID, Name: machine.Name, State: machine.State, ImageRef: cfg.Image, Region: machine.Region, ConfigHash: configHash, Tags: tags}
}

func matchesTags(actual, expected map[string]string) bool {
	for key, value := range expected {
		if actual[key] != value {
			return false
		}
	}
	return true
}

func mapSDKError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, flaps.FlapsErrorNotFound) || flygo.IsNotFoundError(err) {
		return ErrNotFound
	}
	return err
}
