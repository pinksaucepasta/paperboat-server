package lazyaccess

import (
	"errors"
	"testing"
	"time"
)

func TestValidateUpsert(t *testing.T) {
	now := time.Now().UTC()
	valid := UpsertRequest{MachineID: "machine", Target: Target{Scheme: "http", Address: "127.0.0.1:3000"}, AccessMode: "private", OwnershipMode: "persistent_port", ExpiresAt: now.Add(time.Hour)}
	if err := validateUpsert("owner", valid, now); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*UpsertRequest){
		"noncanonical port": func(v *UpsertRequest) { v.Target.Address = "127.0.0.1:03000" },
		"public":            func(v *UpsertRequest) { v.AccessMode = "public" },
		"remote":            func(v *UpsertRequest) { v.Target.Address = "192.0.2.1:80" },
		"url":               func(v *UpsertRequest) { v.Target.Address = "http://127.0.0.1:80/path" },
		"tcp":               func(v *UpsertRequest) { v.Target.Scheme = "tcp" },
		"session":           func(v *UpsertRequest) { v.OwnershipMode = "session" },
		"expired":           func(v *UpsertRequest) { v.ExpiresAt = now },
	} {
		t.Run(name, func(t *testing.T) {
			got := valid
			mutate(&got)
			if !errors.Is(validateUpsert("owner", got, now), ErrInvalid) {
				t.Fatal("accepted invalid policy")
			}
		})
	}
}

func TestDNSValidation(t *testing.T) {
	for _, v := range []string{"preview.pprbt.dev", "a-b.example.test"} {
		if !validDNSName(v) {
			t.Errorf("rejected %q", v)
		}
	}
	for _, v := range []string{"https://preview.test", "bad..test", "-bad.test", "UPPER.test"} {
		if validDNSName(v) {
			t.Errorf("accepted %q", v)
		}
	}
}
