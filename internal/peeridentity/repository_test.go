package peeridentity

import (
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
)

func TestEndpointRequestFromRowAcceptsDeniedTerminalState(t *testing.T) {
	createdAt := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	value, err := endpointRequestFromRow(dbsqlc.PeerEndpointEnrollmentRequest{
		ID:             "per_denied_request",
		UserID:         "usr_denied_request",
		EndpointID:     "cli_denied_request",
		Generation:     1,
		Role:           "cli",
		NoisePublicKey: make([]byte, 32),
		QuicPublicKey:  make([]byte, 32),
		State:          "denied",
		CreatedAt:      createdAt,
		ExpiresAt:      createdAt.Add(5 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if value.State != "denied" {
		t.Fatalf("state=%q, want denied", value.State)
	}
}
