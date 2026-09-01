package db

import (
	"bytes"
	"os"
	"testing"
)

func TestTunnelCertificateCleanupQueryIncludesFailedRowsAndTerminalFence(t *testing.T) {
	body, err := os.ReadFile("queries/tunnel_certificates_v1.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range [][]byte{
		[]byte("state IN ('staged','ready','active','failed')"),
		[]byte("WHERE state IN ('superseded','revoked','failed')"),
		[]byte("state IN ('staged','ready','active','retired','failed')"),
	} {
		if !bytes.Contains(body, required) {
			t.Fatalf("cleanup query missing %q", required)
		}
	}
}
