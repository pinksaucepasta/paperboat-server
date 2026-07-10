package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/pinksaucepasta/paperboat-server/internal/config"
)

func TestExactScopesRejectsMissingDuplicateAndUnknown(t *testing.T) {
	want := []string{"a", "b", "c"}
	for _, tc := range []struct {
		name string
		got  []string
		ok   bool
	}{
		{"exact unordered", []string{"c", "a", "b"}, true},
		{"missing", []string{"a", "b"}, false},
		{"duplicate", []string{"a", "b", "b"}, false},
		{"unknown", []string{"a", "b", "x"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := exactScopes(tc.got, want); got != tc.ok {
				t.Fatalf("exactScopes=%v want=%v", got, tc.ok)
			}
		})
	}
}

func TestPollDistinguishesUnknownClientFromInvalidGrant(t *testing.T) {
	service := NewDeviceService(nil, nil, config.Default().CLIAuth, []string{"test-key"})
	_, err := service.Poll(context.Background(), DeviceTokenInput{ClientID: "unknown", DeviceCode: "code"})
	var deviceErr *DeviceError
	if !errors.As(err, &deviceErr) || deviceErr.Code != "invalid_client" {
		t.Fatalf("error = %v, want invalid_client", err)
	}
	_, err = service.Poll(context.Background(), DeviceTokenInput{ClientID: config.Default().CLIAuth.ClientID})
	if !errors.As(err, &deviceErr) || deviceErr.Code != "invalid_grant" {
		t.Fatalf("error = %v, want invalid_grant", err)
	}
}

func TestListClientsRejectsNonPositiveLimitBeforeQuery(t *testing.T) {
	service := NewDeviceService(nil, nil, config.Default().CLIAuth, []string{"test-key"})
	for _, limit := range []int{0, -1} {
		_, err := service.ListClients(context.Background(), "usr_1", "", "", limit, 0)
		var deviceErr *DeviceError
		if !errors.As(err, &deviceErr) || deviceErr.Code != "validation_failed" {
			t.Fatalf("limit %d error = %v, want validation_failed", limit, err)
		}
	}
}

func TestAuthorizeRejectsInvalidVerificationURLBeforePersistence(t *testing.T) {
	cfg := config.Default().CLIAuth
	cfg.VerificationURL = "dashboard.example.com/cli/authorize"
	service := NewDeviceService(nil, nil, cfg, []string{"test-key"})
	_, err := service.Authorize(context.Background(), DeviceAuthorizationInput{
		ClientID: cfg.ClientID, ClientLabel: "Test CLI", DeviceType: "desktop", OS: "darwin", Scopes: cfg.AllowedScopes,
	})
	if err == nil || err.Error() != "verification URL is invalid" {
		t.Fatalf("error = %v", err)
	}
}

func TestDeviceHashKeyRotationReadsOldAndWritesNew(t *testing.T) {
	service := NewDeviceService(nil, nil, config.Default().CLIAuth, []string{"new-key", "old-key"})
	oldHash := hashWithKey([]byte("old-key"), "credential")
	newHash := hashWithKey([]byte("new-key"), "credential")
	if !service.matchesHash(oldHash, "credential") || !service.matchesHash(newHash, "credential") {
		t.Fatal("key ring did not accept retained hashes")
	}
	if got := service.hash("credential"); got != newHash {
		t.Fatalf("issued hash = %q, want primary-key hash %q", got, newHash)
	}
	if got := service.hashList("credential"); got != newHash+" "+oldHash {
		t.Fatalf("hash candidates = %q", got)
	}
}

func TestUserCodesAreReadableAndNormalizeCaseAndSeparator(t *testing.T) {
	for range 100 {
		code := randomUserCode()
		if len(code) != 9 || code[4] != '-' {
			t.Fatalf("invalid code format %q", code)
		}
		if normalizeUserCode(code) != normalizeUserCode(string([]byte{code[0], code[1], code[2], code[3], code[5], code[6], code[7], code[8]})) {
			t.Fatalf("normalization mismatch for %q", code)
		}
	}
}
