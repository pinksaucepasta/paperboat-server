package httpapi

import (
	"net/http/httptest"
	"testing"
)

func TestRequestNetworkUsesForwardedAddressOnlyFromTrustedProxy(t *testing.T) {
	resolve := newRequestNetwork([]string{"10.0.0.0/8", "2001:db8::/32"})
	tests := []struct {
		name, remote, fly, forwarded, want string
	}{
		{name: "fly client", remote: "10.1.2.3:443", fly: "198.51.100.20", want: "198.51.100.20"},
		{name: "forwarded chain", remote: "10.1.2.3:443", forwarded: "198.51.100.21, 10.2.3.4", want: "198.51.100.21"},
		{name: "untrusted peer cannot spoof", remote: "203.0.113.9:443", fly: "198.51.100.22", forwarded: "198.51.100.23", want: "203.0.113.9"},
		{name: "malformed trusted headers fall back", remote: "10.1.2.3:443", fly: "not-an-ip", forwarded: "also-bad", want: "10.1.2.3"},
		{name: "trusted ipv6 proxy", remote: "[2001:db8::1]:443", fly: "2001:4860::1", want: "2001:4860::1"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/api/auth/device/authorize", nil)
			req.RemoteAddr = tc.remote
			req.Header.Set("Fly-Client-IP", tc.fly)
			req.Header.Set("X-Forwarded-For", tc.forwarded)
			if got := resolve(req); got != tc.want {
				t.Fatalf("network = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestRequestNetworkDefaultsToDirectPeer(t *testing.T) {
	resolve := newRequestNetwork(nil)
	req := httptest.NewRequest("POST", "/api/auth/device/token", nil)
	req.RemoteAddr = "192.0.2.10:1234"
	req.Header.Set("Fly-Client-IP", "198.51.100.30")
	if got := resolve(req); got != "192.0.2.10" {
		t.Fatalf("network = %q", got)
	}
}
