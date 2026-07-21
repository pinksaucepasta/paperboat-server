package fly

import (
	"context"
	"errors"
	"testing"
	"time"
)

type blockingClient struct{ Client }

type requestIDClient struct{ Client }

func (requestIDClient) CreateVolume(context.Context, string, string, int, map[string]string) (Volume, error) {
	return Volume{}, &ProviderError{Outcome: OutcomeUncertain, Operation: "create_volume", RequestID: "req_provider_1", Cause: context.DeadlineExceeded}
}

func (blockingClient) StartMachine(ctx context.Context, _ string) (Machine, error) {
	<-ctx.Done()
	return Machine{}, ctx.Err()
}

func (blockingClient) ListRegions(ctx context.Context) ([]Region, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestTimeoutClientClassifiesMutationAsUncertain(t *testing.T) {
	client := NewTimeoutClient(blockingClient{Client: NewFakeClient()}, 10*time.Millisecond)
	started := time.Now()
	_, err := client.StartMachine(context.Background(), "mach_1")
	if time.Since(started) > time.Second {
		t.Fatal("provider timeout was not bounded")
	}
	var providerErr *ProviderError
	if !errors.As(err, &providerErr) || providerErr.Outcome != OutcomeUncertain || providerErr.Operation != "start_machine" {
		t.Fatalf("error = %#v, want uncertain start_machine", err)
	}
}

func TestTimeoutClientClassifiesReadAsRetryable(t *testing.T) {
	client := NewTimeoutClient(blockingClient{Client: NewFakeClient()}, 10*time.Millisecond)
	_, err := client.ListRegions(context.Background())
	var providerErr *ProviderError
	if !errors.As(err, &providerErr) || providerErr.Outcome != OutcomeRetryable || providerErr.Operation != "list_regions" {
		t.Fatalf("error = %#v, want retryable list_regions", err)
	}
}

func TestTimeoutClientPreservesProviderRequestID(t *testing.T) {
	client := NewTimeoutClient(requestIDClient{Client: NewFakeClient()}, time.Second)
	_, err := client.CreateVolume(context.Background(), "volume", "iad", 10, nil)
	var providerErr *ProviderError
	if !errors.As(err, &providerErr) || providerErr.RequestID != "req_provider_1" {
		t.Fatalf("error = %#v, want provider request ID", err)
	}
}
