package peeridentity

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"testing"
	"time"
)

type recordingRepository struct {
	operation string
	userID    string
	value     Certificate
	err       error
	root      AccountRoot
	request   MachineEndpointRequest
}

func (r *recordingRepository) Bootstrap(_ context.Context, operation, userID string, root ed25519.PublicKey, value Certificate) (Certificate, error) {
	r.operation, r.userID, r.value = operation, userID, value
	r.root = AccountRoot{PublicKey: append(ed25519.PublicKey(nil), root...), Fingerprint: sha256.Sum256(root), Generation: 1}
	return value, r.err
}

func (r *recordingRepository) RequestMachineEndpoint(_ context.Context, request MachineEndpointRequest, id string, _ [sha256.Size]byte, expires time.Time) (EndpointEnrollmentRequest, error) {
	r.request = request
	return EndpointEnrollmentRequest{ID: id, UserID: request.UserID, EndpointID: request.EndpointID, Generation: request.Generation, Role: RoleMachine, State: "pending", NoisePublicKey: request.NoisePublicKey, QUICPublicKey: request.QUICPublicKey, CreatedAt: request.Now, ExpiresAt: expires}, r.err
}

func (r *recordingRepository) ListPendingEndpoints(context.Context, string, time.Time, int32) ([]EndpointEnrollmentRequest, error) {
	return nil, r.err
}

func (r *recordingRepository) Get(context.Context, string, string, uint64, time.Time) (Certificate, error) {
	return r.value, r.err
}

func (r *recordingRepository) Revoke(context.Context, string, string, string, uint64, uint64, string, time.Time) (Certificate, error) {
	return r.value, r.err
}

func (r *recordingRepository) ResolveAccountRoot(context.Context, string) (AccountRoot, error) {
	return r.root, r.err
}

func (r *recordingRepository) Register(_ context.Context, operation, userID string, value Certificate, _ time.Time) (Certificate, error) {
	r.operation, r.userID, r.value = operation, userID, value
	return value, r.err
}

func (r *recordingRepository) GetEndpointRequest(context.Context, string, string, time.Time) (EndpointEnrollmentRequest, error) {
	return EndpointEnrollmentRequest{}, r.err
}

func (r *recordingRepository) DenyEndpointRequest(context.Context, string, string, string, time.Time) (EndpointEnrollmentRequest, error) {
	return EndpointEnrollmentRequest{}, r.err
}

func TestServiceRegistersOnlyVerifiedCertificateFields(t *testing.T) {
	repository := &recordingRepository{}
	service, err := NewService(repository)
	if err != nil {
		t.Fatal(err)
	}
	rootPublic, rootPrivate, _ := ed25519.GenerateKey(nil)
	repository.root = AccountRoot{PublicKey: rootPublic, Fingerprint: sha256.Sum256(rootPublic), Generation: 1}
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	raw := signedFixture(t, rootPrivate, "account_01", RoleMachine, "machine_01", 3, 7, now.Add(-time.Minute), now.Add(time.Hour))
	certificateFingerprint := sha256.Sum256(raw)
	value, err := service.Register(context.Background(), RegisterRequest{
		OperationID: "operation_endpoint_01", UserID: "account_01",
		Certificate: raw, Expected: Expected{AccountID: "account_01", Role: RoleMachine, EndpointID: "machine_01", Generation: 3, Serial: 7},
		ExpectedRootFingerprint: repository.root.Fingerprint, ExpectedCertificateFingerprint: certificateFingerprint,
		ExpectedIssuedAt: now.Add(-time.Minute), ExpectedExpiresAt: now.Add(time.Hour), Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if repository.operation != "operation_endpoint_01" || repository.userID != "account_01" || repository.value.Fingerprint != value.Fingerprint || repository.value.EndpointID != "machine_01" {
		t.Fatalf("repository=%+v", repository)
	}
}

func TestServiceBootstrapsOnlySessionBoundCLIIdentity(t *testing.T) {
	repository := &recordingRepository{}
	service, _ := NewService(repository)
	rootPublic, rootPrivate, _ := ed25519.GenerateKey(nil)
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	raw := signedFixture(t, rootPrivate, "account_01", RoleCLI, "cli_session_01", 1, 1, now, now.Add(time.Hour))
	fingerprint := sha256.Sum256(raw)
	value, err := service.Bootstrap(context.Background(), BootstrapRequest{RegisterRequest: RegisterRequest{OperationID: "operation_bootstrap_01", UserID: "account_01", Certificate: raw, Expected: Expected{AccountID: "account_01", Role: RoleCLI, EndpointID: "cli_session_01", Generation: 1, Serial: 1}, ExpectedRootFingerprint: sha256.Sum256(rootPublic), ExpectedCertificateFingerprint: fingerprint, ExpectedIssuedAt: now, ExpectedExpiresAt: now.Add(time.Hour), Now: now}, CLIClientSessionID: "cli_session_01", RootPublicKey: rootPublic})
	if err != nil || value.EndpointID != "cli_session_01" || repository.root.Fingerprint != sha256.Sum256(rootPublic) {
		t.Fatalf("value=%+v repository=%+v err=%v", value, repository, err)
	}
	request := BootstrapRequest{RegisterRequest: RegisterRequest{OperationID: "operation_bootstrap_02", UserID: "account_01", Certificate: raw, Expected: Expected{AccountID: "account_01", Role: RoleCLI, EndpointID: "other_cli", Generation: 1, Serial: 1}, ExpectedRootFingerprint: sha256.Sum256(rootPublic), ExpectedCertificateFingerprint: fingerprint, ExpectedIssuedAt: now, ExpectedExpiresAt: now.Add(time.Hour), Now: now}, CLIClientSessionID: "cli_session_01", RootPublicKey: rootPublic}
	if _, err := service.Bootstrap(context.Background(), request); !errors.Is(err, ErrInvalid) {
		t.Fatalf("session substitution error=%v", err)
	}
}

func TestServiceRejectsBeforePersistence(t *testing.T) {
	repository := &recordingRepository{}
	service, _ := NewService(repository)
	rootPublic, rootPrivate, _ := ed25519.GenerateKey(nil)
	repository.root = AccountRoot{PublicKey: rootPublic, Fingerprint: sha256.Sum256(rootPublic), Generation: 1}
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	raw := signedFixture(t, rootPrivate, "account_01", RoleCLI, "cli_01", 1, 1, now.Add(-time.Minute), now.Add(time.Hour))
	raw[len(raw)-1] ^= 1
	certificateFingerprint := sha256.Sum256(raw)
	_, err := service.Register(context.Background(), RegisterRequest{
		OperationID: "operation_endpoint_01", UserID: "account_01",
		Certificate: raw, Expected: Expected{AccountID: "account_01", Role: RoleCLI, EndpointID: "cli_01", Generation: 1},
		ExpectedRootFingerprint: repository.root.Fingerprint, ExpectedCertificateFingerprint: certificateFingerprint,
		ExpectedIssuedAt: now.Add(-time.Minute), ExpectedExpiresAt: now.Add(time.Hour), Now: now,
	})
	if !errors.Is(err, ErrSignature) || repository.operation != "" {
		t.Fatalf("error=%v repository=%+v", err, repository)
	}
	var typedNil *recordingRepository
	if _, err := NewService(typedNil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("typed nil error=%v", err)
	}
}

func TestServiceCreatesBoundedMachineEndpointRequestAndSafetyCode(t *testing.T) {
	repository := &recordingRepository{}
	service, _ := NewService(repository)
	now := time.Date(2026, 8, 3, 12, 0, 0, 0, time.UTC)
	request := MachineEndpointRequest{OperationID: "operation_machine_endpoint_01", UserID: "account_01", EndpointID: "machine_01", Generation: 4, NoisePublicKey: [32]byte{1}, QUICPublicKey: [32]byte{2}, Now: now}
	value, err := service.RequestMachineEndpoint(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if repository.request != request || value.ID == "" || value.ExpiresAt != now.Add(5*time.Minute) || value.SafetyCode() != "869b8-a2307" {
		t.Fatalf("value=%+v code=%s request=%+v", value, value.SafetyCode(), repository.request)
	}
	request.NoisePublicKey = [32]byte{}
	if _, err := service.RequestMachineEndpoint(context.Background(), request); !errors.Is(err, ErrInvalid) {
		t.Fatalf("zero key error=%v", err)
	}
}
