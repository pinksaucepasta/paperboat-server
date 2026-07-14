package metering_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/billing"
	"github.com/pinksaucepasta/paperboat-server/internal/fly"
	"github.com/pinksaucepasta/paperboat-server/internal/metering"
)

// flakyFlyClient wraps the fake Fly client and returns a non-NotFound error for
// a single machine ID, simulating a transient Fly API failure (rate limit, 5xx,
// network) on one project's poll.
type flakyFlyClient struct {
	*fly.FakeClient
	failMachineID string
}

func (c *flakyFlyClient) GetMachine(ctx context.Context, machineID string) (fly.Machine, error) {
	if machineID == c.failMachineID {
		return fly.Machine{}, errors.New("fly api: 429 too many requests")
	}
	return c.FakeClient.GetMachine(ctx, machineID)
}

// TestRuntimeMeteringEnforcesIdleDespitePollError proves that a transient Fly
// poll failure on one machine does not prevent idle enforcement for a different,
// genuinely idle project.
func TestRuntimeMeteringEnforcesIdleDespitePollError(t *testing.T) {
	store := openRuntimeTestDB(t)
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())

	// A genuinely idle project that must be stopped.
	idleUser := seedMeteredProject(t, store, suffix, "idlepoll", "mach_idlepoll_"+suffix, "standard-1x", "1", 60)
	billingRepo := billing.NewRepository(store)
	if err := billingRepo.GrantCredits(ctx, idleUser, "grant_idlepoll_"+suffix, "grant-idlepoll-"+suffix, "test", suffix, "10", nil); err != nil {
		t.Fatal(err)
	}
	// A second project whose Fly poll will fail.
	seedMeteredProjectForUser(t, store, suffix+"_bad", idleUser, "badpoll", "mach_badpoll_"+suffix, "standard-1x", "1", 60)

	fake := fly.NewFakeClient()
	fake.Machines["mach_idlepoll_"+suffix] = fly.Machine{ID: "mach_idlepoll_" + suffix, State: "running"}
	fake.Machines["mach_badpoll_"+suffix] = fly.Machine{ID: "mach_badpoll_" + suffix, State: "running"}
	flaky := &flakyFlyClient{FakeClient: fake, failMachineID: "mach_badpoll_" + suffix}

	service := metering.NewRuntimeService(store, flaky, billingRepo)
	start := time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC)
	service.SetClock(func() time.Time { return start })
	_ = service.RunOnce(ctx) // opens intervals; may error due to the flaky poll
	service.SetClock(func() time.Time { return start.Add(61 * time.Second) })
	_ = service.RunOnce(ctx) // past the idle deadline

	assertQueuedStop(t, store, "prj_idlepoll_"+suffix, "project.stop.idle_timeout:prj_idlepoll_"+suffix)
}
