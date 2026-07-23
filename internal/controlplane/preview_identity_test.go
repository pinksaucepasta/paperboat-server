package controlplane

import (
	"strings"
	"testing"
)

func TestPreviewIdentityStableAndCounterBound(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	first, err := PreviewIdentity(key, "env_test_01", "web", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 28 || !strings.HasPrefix(first, "p-") {
		t.Fatalf("unexpected key %q", first)
	}
	again, err := PreviewIdentity(key, "env_test_01", "web", 0)
	if err != nil || again != first {
		t.Fatalf("identity is not stable: %q / %v", again, err)
	}
	for _, counter := range []uint64{1, 2, 100} {
		other, err := PreviewIdentity(key, "env_test_01", "web", counter)
		if err != nil || other == first {
			t.Fatalf("counter %d did not derive a distinct key: %q / %v", counter, other, err)
		}
	}
}

func TestPreviewHostnameValidation(t *testing.T) {
	host, err := PreviewHostname("Preview.Example.Test.", "p-abcdefghijklmnopqrstuvwxyz")
	if err != nil || host != "p-abcdefghijklmnopqrstuvwxyz.preview.example.test" {
		t.Fatalf("hostname = %q, err = %v", host, err)
	}
	for _, domain := range []string{"", "127.0.0.1", "bad host"} {
		if _, err := PreviewHostname(domain, "p-abcdefghijklmnopqrstuvwxyz"); err == nil {
			t.Fatalf("domain %q unexpectedly accepted", domain)
		}
	}
}

func TestPreviewIdentityRejectsShortKeyAndNUL(t *testing.T) {
	if _, err := PreviewIdentity([]byte("short"), "env", "web", 0); err != ErrPreviewKeyInvalid {
		t.Fatalf("short key error = %v", err)
	}
	if _, err := PreviewIdentity(make([]byte, 32), "env\x00", "web", 0); err != ErrPreviewIdentityInvalid {
		t.Fatalf("NUL error = %v", err)
	}
}
