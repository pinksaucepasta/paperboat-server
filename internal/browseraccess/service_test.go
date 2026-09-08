package browseraccess

import (
	"strings"
	"testing"
)

func TestBrowserInputValidation(t *testing.T) {
	for _, host := range []string{"app.preview.pprbt.dev", "opaque.tunnels.pprbt.dev"} {
		if got, err := validHost(host); err != nil || got != host {
			t.Fatalf("validHost(%q)=(%q,%v)", host, got, err)
		}
	}
	for _, host := range []string{"", "example.test:443", "user@example.test", "example.test/path", "example.test\\path"} {
		if _, err := validHost(host); err == nil {
			t.Fatalf("validHost(%q) succeeded", host)
		}
	}
	for _, path := range []string{"/", "/hello?next=%2Fok", "/a#fragment"} {
		if !validReturn(path) {
			t.Fatalf("validReturn(%q)=false", path)
		}
	}
	for _, path := range []string{"", "relative", "//evil.test", "/\\evil.test", "https://evil.test", "/bad\npath", "/" + strings.Repeat("x", 2048)} {
		if validReturn(path) {
			t.Fatalf("validReturn(%q)=true", path)
		}
	}
}

func TestOpaqueSecretsAndConstantTimeDigest(t *testing.T) {
	a, err := secret("bah_")
	if err != nil {
		t.Fatal(err)
	}
	b, err := secret("bah_")
	if err != nil {
		t.Fatal(err)
	}
	if a == b || !strings.HasPrefix(a, "bah_") {
		t.Fatalf("invalid opaque secrets")
	}
	h := digest(a)
	if !equalHash(h[:], h) || equalHash(h[:], digest(b)) {
		t.Fatalf("digest comparison failed")
	}
}

func TestNewServiceRequiresExactHTTPSOrigin(t *testing.T) {
	for _, origin := range []string{"http://login.example.test", "https://login.example.test/path", "https://user@login.example.test", "https://login.example.test?x=1"} {
		if _, err := NewService(nil, origin); err == nil {
			t.Fatalf("NewService accepted %q", origin)
		}
	}
	s, err := NewService(nil, "https://login.example.test/")
	if err != nil || s.trustedOrigin != "https://login.example.test" {
		t.Fatalf("NewService valid origin: %#v %v", s, err)
	}
}
