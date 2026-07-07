package fly

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func TestSDKClientFlySmoke(t *testing.T) {
	if os.Getenv("PAPERBOAT_RUN_FLY_SMOKE") != "1" {
		t.Skip("set PAPERBOAT_RUN_FLY_SMOKE=1 to run real Fly smoke test")
	}
	token := strings.TrimSpace(os.Getenv("PAPERBOAT_FLY_API_TOKEN"))
	appName := strings.TrimSpace(os.Getenv("PAPERBOAT_FLY_APP_NAME"))
	orgSlug := strings.TrimSpace(os.Getenv("PAPERBOAT_FLY_ORG_SLUG"))
	imageRef := strings.TrimSpace(os.Getenv("PAPERBOAT_FLY_IMAGE_REF"))
	if token == "" || appName == "" || orgSlug == "" || imageRef == "" {
		t.Fatal("PAPERBOAT_FLY_API_TOKEN, PAPERBOAT_FLY_APP_NAME, PAPERBOAT_FLY_ORG_SLUG, and PAPERBOAT_FLY_IMAGE_REF are required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	suffix := fmt.Sprintf("%d", time.Now().UnixNano()%1_000_000_000)
	client := &SDKClient{APIToken: token, AppName: appName, OrgSlug: orgSlug}
	volume, err := client.CreateVolume(ctx, "pbsmoke_"+suffix, "iad", 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := client.DestroyVolume(context.Background(), volume.ID); err != nil && !strings.Contains(err.Error(), "could not find") {
			t.Logf("cleanup volume %s: %v", volume.ID, err)
		}
	}()

	machine, err := client.CreateMachine(ctx, MachineSpec{
		Name:      "pbsmoke-" + suffix,
		ImageRef:  imageRef,
		Region:    "iad",
		Size:      MachineSize{VCPU: 1, MemoryMB: 256},
		VolumeID:  volume.ID,
		MountPath: "/workspace",
		Env:       map[string]string{"PAPERBOAT_SMOKE": "1"},
		Command:   []string{"nginx", "-g", "daemon off;"},
		Tags: map[string]string{
			"managed_by":           "paperboat-server",
			"paperboat_project_id": "smoke-" + suffix,
		},
		ConfigHash: "smoke-" + suffix,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := client.DestroyMachine(context.Background(), machine.ID); err != nil && !strings.Contains(err.Error(), "could not find") {
			t.Logf("cleanup machine %s: %v", machine.ID, err)
		}
	}()

	got, err := client.GetMachine(ctx, machine.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != machine.ID || got.ImageRef == "" || got.ConfigHash == "" {
		t.Fatalf("machine = %#v", got)
	}
}
