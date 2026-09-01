package controlplane

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/mint"
)

func TestVerifyMachineControlRequestRejectsHelperCredentialWithoutFallback(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	signer, err := mint.NewEphemeral(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	helper, err := signer.SignCredential(mint.CredentialInput{
		Issuer: "https://api.example.test", Audience: "paperboat-control", Subject: "helper_1",
		JTI: "helper_jti_1", IssuedAt: now, ExpiresAt: now.Add(time.Hour),
		CredentialClass: "helper_identity", Scopes: []string{"helper:connect", "helper:renew"},
		EnvironmentID: "environment_1", HelperID: "helper_1", MachineID: "machine_1",
		KeyThumbprint: "sha256:helper",
	})
	if err != nil {
		t.Fatal(err)
	}
	service := &EnrollmentService{signer: signer, issuer: "https://api.example.test", clock: func() time.Time { return now }}
	if _, err := service.VerifyMachineControlRequest(context.Background(), helper, []byte("proof"), "POST", "/v1/edge/private-access/grants", []byte(`{}`)); !errors.Is(err, ErrHelperProof) {
		t.Fatalf("helper credential error=%v, want ErrHelperProof", err)
	}
}
