package lazyaccess

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRuntimeBootValidation(t *testing.T) {
	for _, boot := range []string{"0123456789ABCdef_-", "boot_lazy_runtime_1234567890"} {
		if !validRuntimeBoot(boot) {
			t.Errorf("valid boot rejected: %q", boot)
		}
	}
	for _, boot := range []string{"short", "boot_lazy_1234567/", "boot_lazy_1234567.", "boot_lazy_1234567é", "boot_lazy_1234567\n", "boot_lazy_1234567\\"} {
		if validRuntimeBoot(boot) {
			t.Errorf("invalid boot accepted: %q", boot)
		}
	}
}

func TestActivationAuthorizationDeadline(t *testing.T) {
	denied := errors.New("denied")
	if err := checkActivation(context.Background(), func(context.Context) error { return denied }); !errors.Is(err, denied) {
		t.Fatal("live authorization denial changed", err)
	}
	expired, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if err := checkActivation(expired, func(ctx context.Context) error { return ctx.Err() }); !activationCode(err, "activation_timeout") {
		t.Fatal("deadline did not produce activation_timeout", err)
	}
}
