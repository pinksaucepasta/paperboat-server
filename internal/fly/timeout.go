package fly

import (
	"context"
	"errors"
	"time"
)

type TimeoutClient struct {
	client  Client
	timeout time.Duration
}

func NewTimeoutClient(client Client, timeout time.Duration) Client {
	if client == nil || timeout <= 0 {
		return client
	}
	return &TimeoutClient{client: client, timeout: timeout}
}

func (c *TimeoutClient) bound(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, c.timeout)
}

func timeoutError(ctx context.Context, operation string, mutation bool, err error) error {
	if err == nil {
		return nil
	}
	if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) && ctx.Err() == nil {
		return err
	}
	outcome := OutcomeRetryable
	if mutation {
		outcome = OutcomeUncertain
	}
	requestID := ""
	var providerErr *ProviderError
	if errors.As(err, &providerErr) {
		requestID = providerErr.RequestID
	}
	return &ProviderError{Outcome: outcome, Operation: operation, RequestID: requestID, Cause: err}
}

func (c *TimeoutClient) ListRegions(ctx context.Context) ([]Region, error) {
	bounded, cancel := c.bound(ctx)
	defer cancel()
	result, err := c.client.ListRegions(bounded)
	return result, timeoutError(bounded, "list_regions", false, err)
}

func (c *TimeoutClient) CreateVolume(ctx context.Context, name, region string, sizeGB int, tags map[string]string) (Volume, error) {
	bounded, cancel := c.bound(ctx)
	defer cancel()
	result, err := c.client.CreateVolume(bounded, name, region, sizeGB, tags)
	return result, timeoutError(bounded, "create_volume", true, err)
}

func (c *TimeoutClient) GetVolume(ctx context.Context, id string) (Volume, error) {
	bounded, cancel := c.bound(ctx)
	defer cancel()
	result, err := c.client.GetVolume(bounded, id)
	return result, timeoutError(bounded, "get_volume", false, err)
}

func (c *TimeoutClient) ListVolumes(ctx context.Context) ([]Volume, error) {
	bounded, cancel := c.bound(ctx)
	defer cancel()
	result, err := c.client.ListVolumes(bounded)
	return result, timeoutError(bounded, "list_volumes", false, err)
}

func (c *TimeoutClient) DestroyVolume(ctx context.Context, id string) error {
	bounded, cancel := c.bound(ctx)
	defer cancel()
	return timeoutError(bounded, "destroy_volume", true, c.client.DestroyVolume(bounded, id))
}

func (c *TimeoutClient) CreateMachine(ctx context.Context, spec MachineSpec) (Machine, error) {
	bounded, cancel := c.bound(ctx)
	defer cancel()
	result, err := c.client.CreateMachine(bounded, spec)
	return result, timeoutError(bounded, "create_machine", true, err)
}

func (c *TimeoutClient) GetMachine(ctx context.Context, id string) (Machine, error) {
	bounded, cancel := c.bound(ctx)
	defer cancel()
	result, err := c.client.GetMachine(bounded, id)
	return result, timeoutError(bounded, "get_machine", false, err)
}

func (c *TimeoutClient) UpdateMachine(ctx context.Context, id string, spec MachineSpec) (Machine, error) {
	bounded, cancel := c.bound(ctx)
	defer cancel()
	result, err := c.client.UpdateMachine(bounded, id, spec)
	return result, timeoutError(bounded, "update_machine", true, err)
}

func (c *TimeoutClient) StartMachine(ctx context.Context, id string) (Machine, error) {
	bounded, cancel := c.bound(ctx)
	defer cancel()
	result, err := c.client.StartMachine(bounded, id)
	return result, timeoutError(bounded, "start_machine", true, err)
}

func (c *TimeoutClient) StopMachine(ctx context.Context, id string) (Machine, error) {
	bounded, cancel := c.bound(ctx)
	defer cancel()
	result, err := c.client.StopMachine(bounded, id)
	return result, timeoutError(bounded, "stop_machine", true, err)
}

func (c *TimeoutClient) DestroyMachine(ctx context.Context, id string) error {
	bounded, cancel := c.bound(ctx)
	defer cancel()
	return timeoutError(bounded, "destroy_machine", true, c.client.DestroyMachine(bounded, id))
}

func (c *TimeoutClient) ListMachines(ctx context.Context, tags map[string]string) ([]Machine, error) {
	bounded, cancel := c.bound(ctx)
	defer cancel()
	result, err := c.client.ListMachines(bounded, tags)
	return result, timeoutError(bounded, "list_machines", false, err)
}

func (c *TimeoutClient) SetSecret(ctx context.Context, name, value string) error {
	bounded, cancel := c.bound(ctx)
	defer cancel()
	return timeoutError(bounded, "set_secret", true, c.client.SetSecret(bounded, name, value))
}

func (c *TimeoutClient) DeleteSecret(ctx context.Context, name string) error {
	bounded, cancel := c.bound(ctx)
	defer cancel()
	return timeoutError(bounded, "delete_secret", true, c.client.DeleteSecret(bounded, name))
}
