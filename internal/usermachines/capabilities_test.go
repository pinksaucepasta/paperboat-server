package usermachines

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"testing"

	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
)

func TestDeviceCapabilityNamesAreUnifiedAndRelayOptIn(t *testing.T) {
	defaults := DeviceCapabilitySelection{Terminal: true, ManagedSSH: true, FileReceive: true, PreviewTunnel: true}
	want := []string{"file_receive", "preview_launch", "terminal_host", "codex_host", "session_host", "ssh_host"}
	if got := capabilityNames(defaults); !reflect.DeepEqual(got, want) {
		t.Fatalf("default names=%q want=%q", got, want)
	}
	if selectionFromNames(want).PeerRelay {
		t.Fatal("peer relay must remain opt-in")
	}
	defaults.PeerRelay = true
	if !selectionFromNames(capabilityNames(defaults)).PeerRelay {
		t.Fatal("explicit peer relay selection was lost")
	}
}

func TestMapDeviceCapabilityPolicySeparatesDesiredAndApplied(t *testing.T) {
	machine := dbsqlc.UserMachine{
		ConfiguredCapabilities:     []string{"file_receive", "ssh_host", "peer_relay"},
		ObservedCapabilities:       []string{"file_receive"},
		CapabilitiesDesiredVersion: 4, CapabilitiesObservedVersion: 3,
		CapabilitiesStatus: "pending", CapabilitiesErrorCode: sql.NullString{},
	}
	got := mapDeviceCapabilityPolicy(machine)
	if got.Schema != DeviceCapabilitiesSchemaV1 || got.DesiredVersion != 4 || got.AppliedVersion != 3 || !got.Desired.ManagedSSH || !got.Desired.PeerRelay || got.Applied.ManagedSSH || got.Status != "pending" {
		t.Fatalf("policy=%+v", got)
	}
}

func TestDeviceCapabilityMutationRejectsInvalidAuthorityBeforeStorage(t *testing.T) {
	service := &Service{}
	for _, input := range []struct {
		user, machine, key string
		version            int64
	}{
		{"", "mch_1", "capability-operation", 1},
		{"usr_1", "", "capability-operation", 1},
		{"usr_1", "mch_1", "short", 1},
		{"usr_1", "mch_1", "capability-operation", 0},
	} {
		if _, err := service.SetDeviceCapabilities(context.Background(), input.user, input.machine, input.key, DeviceCapabilitySelection{}, input.version); !errors.Is(err, ErrCapabilitiesInvalid) {
			t.Fatalf("input=%+v error=%v", input, err)
		}
	}
}
