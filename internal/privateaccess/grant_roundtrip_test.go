package privateaccess

import (
	"context"
	"crypto/ed25519"
	"reflect"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/mint"
)

func TestMintGrantIssuerRoundTripsEveryAuthorizationFence(t *testing.T) {
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index + 1)
	}
	provider, err := mint.New([]mint.Key{{ID: "private-access-key", PrivateKey: ed25519.NewKeyFromSeed(seed)}}, "private-access-key", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := NewMintGrantIssuer(provider, "https://api.example.test")
	if err != nil {
		t.Fatal(err)
	}
	request := Request{
		AccountID: "account_1", ResourceKind: ResourcePreview, ResourceID: "preview_1", RouteID: "route_1",
		Audience: AudiencePreviewHTTP, DeviceID: "machine_1", SessionID: "installation_7", InstallationGeneration: 7,
		ExpiresAt: now.Add(time.Minute), Nonce: "nonce_private_access_1", OperationID: "operation_preview_1",
		CarrierSessionID: "carrier_session_1", RouteGeneration: 2, SessionGeneration: 3, ProcessGeneration: 4,
		ConfigGeneration: 5, AssignmentGeneration: 6, EdgeNodeID: "edge_1", EdgeProcessEpoch: "epoch_001",
		Protocol: ProtocolHTTP, Method: "CONNECT", Host: "private.example.test", Path: "/",
		IdempotencyKey: "private_access_idempotency_1", RequestID: "request_001", CorrelationID: "correlation_001",
	}
	token, err := issuer.MintGrant(context.Background(), request, now)
	if err != nil {
		t.Fatal(err)
	}
	got, err := issuer.VerifyGrant(context.Background(), token, now)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, request) {
		t.Fatalf("verified request = %#v, want %#v", got, request)
	}
}
