package managedssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

type fakeRepository struct {
	client ClientKey
	host   HostKeySet
	target MachineTarget
	err    error
}

func (r *fakeRepository) RegisterClient(_ context.Context, _ RegisterClientRequest, key ClientKey) (ClientKey, error) {
	r.client = key
	return key, r.err
}
func (r *fakeRepository) RevokeClient(_ context.Context, request RevokeClientRequest) (ClientKey, error) {
	result := r.client
	result.State, result.RevokedAt, result.RevocationReason = "revoked", request.Now, request.Reason
	return result, r.err
}
func (r *fakeRepository) ListClientKeys(_ context.Context, request ListClientKeysRequest) (ClientKeySet, error) {
	return ClientKeySet{UserMachineID: request.UserMachineID, MachineGeneration: request.MachineGeneration, Keys: []ClientKey{r.client}}, r.err
}
func (r *fakeRepository) ObserveHost(_ context.Context, _ ObserveHostRequest, set HostKeySet) (HostKeySet, error) {
	r.host = set
	return set, r.err
}
func (r *fakeRepository) PromoteHost(_ context.Context, request PromoteHostRequest) (HostKeySet, error) {
	result := r.host
	result.State, result.PromotedAt = "active", request.Now
	return result, r.err
}
func (r *fakeRepository) GetActiveHost(_ context.Context, _ GetHostKeySetRequest) (HostKeySet, error) {
	return r.host, r.err
}
func (r *fakeRepository) GetPendingHost(_ context.Context, _ GetHostKeySetRequest) (HostKeySet, error) {
	return r.host, r.err
}
func (r *fakeRepository) RegisterTarget(_ context.Context, request RegisterTargetRequest) (MachineTarget, error) {
	r.target = MachineTarget{UserMachineID: request.UserMachineID, MachineGeneration: request.MachineGeneration, OSUser: request.OSUser, TargetPort: request.TargetPort, ReconciliationVersion: 1, CreatedAt: request.Now, UpdatedAt: request.Now}
	return r.target, r.err
}
func (r *fakeRepository) UpdateTargetPort(_ context.Context, request UpdateTargetPortRequest) (MachineTarget, error) {
	r.target.TargetPort, r.target.ReconciliationVersion, r.target.UpdatedAt = request.TargetPort, request.ExpectedReconciliationVersion+1, request.Now
	return r.target, r.err
}
func (r *fakeRepository) GetTarget(_ context.Context, _ GetTargetRequest) (MachineTarget, error) {
	return r.target, r.err
}

func TestServiceCanonicalizesManagedClientEd25519Key(t *testing.T) {
	repository := &fakeRepository{}
	service, _ := NewService(repository)
	now := time.Unix(1_800_000_000, 0).UTC()
	line := publicLine(t, "ed25519") + " workstation comment"
	result, err := service.RegisterClient(context.Background(), RegisterClientRequest{OperationID: "operation_managed_ssh_01", UserID: "user_01", CLIClientSessionID: "client_01", PublicKey: line, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if result.Algorithm != ssh.KeyAlgoED25519 || result.PublicKey == line || strings.Contains(result.PublicKey, "comment") || result.Fingerprint == [32]byte{} || result.State != "active" || result.ReconciliationVersion != 1 || result.CreatedAt != now {
		t.Fatalf("key=%+v", result)
	}
	if _, err := service.RegisterClient(context.Background(), RegisterClientRequest{OperationID: "operation_managed_ssh_01", UserID: "user_01", CLIClientSessionID: "client_01", PublicKey: publicLine(t, "rsa"), Now: now}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("RSA client key error=%v", err)
	}
	if _, err := service.RegisterClient(context.Background(), RegisterClientRequest{OperationID: "operation_managed_ssh_01", UserID: "user_01", CLIClientSessionID: "client_01", PublicKey: "command=\"id\" " + publicLine(t, "ed25519"), Now: now}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("authorized_keys option error=%v", err)
	}
}

func TestServiceHostSetFingerprintIsOrderIndependentAndRejectsDuplicates(t *testing.T) {
	repository := &fakeRepository{}
	service, _ := NewService(repository)
	now := time.Unix(1_800_000_000, 0).UTC()
	first, second := publicLine(t, "ed25519"), publicLine(t, "rsa")
	request := ObserveHostRequest{OperationID: "operation_managed_ssh_01", SetID: "sshks_abcdefghijklmnop", UserID: "user_01", UserMachineID: "machine_01", MachineGeneration: 2, ObservationGeneration: 3, PublicKeys: []string{first, second}, Now: now}
	left, err := service.ObserveHost(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	request.ObservationGeneration++
	request.PublicKeys = []string{second, first}
	right, err := service.ObserveHost(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if left.Fingerprint != right.Fingerprint || len(left.Keys) != 2 || left.Keys[0].Fingerprint == left.Keys[1].Fingerprint {
		t.Fatalf("left=%+v right=%+v", left, right)
	}
	request.PublicKeys = []string{first, first}
	if _, err := service.ObserveHost(context.Background(), request); !errors.Is(err, ErrInvalid) {
		t.Fatalf("duplicate error=%v", err)
	}
}

func TestServiceValidatesRevocationAndPromotion(t *testing.T) {
	repository := &fakeRepository{}
	service, _ := NewService(repository)
	now := time.Now().UTC()
	if _, err := service.RevokeClient(context.Background(), RevokeClientRequest{OperationID: "operation_managed_ssh_01", ActorUserID: "user_01", Fingerprint: [32]byte{1}, Reason: "unknown", Now: now}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("revocation error=%v", err)
	}
	if _, err := service.PromoteHost(context.Background(), PromoteHostRequest{OperationID: "operation_managed_ssh_01", ActorUserID: "user_01", UserMachineID: "machine_01", MachineGeneration: 1, SetID: "sshks_abcdefghijklmnop", Now: now}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("promotion error=%v", err)
	}
	for _, id := range []string{"sshks_short", "sshks_abcdefghijklmn!p", "other_abcdefghijklmnop"} {
		if _, err := service.ObserveHost(context.Background(), ObserveHostRequest{OperationID: "operation_managed_ssh_01", SetID: id, UserID: "user_01", UserMachineID: "machine_01", MachineGeneration: 1, ObservationGeneration: 1, PublicKeys: []string{publicLine(t, "ed25519")}, Now: now}); !errors.Is(err, ErrInvalid) {
			t.Fatalf("set ID %q error=%v", id, err)
		}
	}
}

func TestServiceValidatesMachineTarget(t *testing.T) {
	repository := &fakeRepository{}
	service, _ := NewService(repository)
	now := time.Unix(1_800_000_000, 0).UTC()
	target, err := service.RegisterTarget(context.Background(), RegisterTargetRequest{OperationID: "operation_managed_ssh_01", ActorUserID: "user_01", UserMachineID: "machine_01", MachineGeneration: 2, OSUser: "deploy", TargetPort: 2222, Now: now})
	if err != nil || target.OSUser != "deploy" || target.TargetPort != 2222 || target.MachineGeneration != 2 {
		t.Fatalf("target=%+v error=%v", target, err)
	}
	for _, user := range []string{"", "-root", "bad user", "user@host", "bad\nuser"} {
		if _, err := service.RegisterTarget(context.Background(), RegisterTargetRequest{OperationID: "operation_managed_ssh_01", ActorUserID: "user_01", UserMachineID: "machine_01", MachineGeneration: 2, OSUser: user, TargetPort: 22, Now: now}); !errors.Is(err, ErrInvalid) {
			t.Fatalf("OS user %q error=%v", user, err)
		}
	}
	if _, err := service.UpdateTargetPort(context.Background(), UpdateTargetPortRequest{OperationID: "operation_managed_ssh_01", ActorUserID: "user_01", UserMachineID: "machine_01", MachineGeneration: 2, TargetPort: 22, Now: now}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("missing reconciliation version error=%v", err)
	}
}

func publicLine(t *testing.T, kind string) string {
	t.Helper()
	var public any
	var err error
	if kind == "rsa" {
		var private *rsa.PrivateKey
		private, err = rsa.GenerateKey(rand.Reader, 2048)
		if err == nil {
			public = &private.PublicKey
		}
	} else {
		public, _, err = ed25519.GenerateKey(rand.Reader)
	}
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
}
