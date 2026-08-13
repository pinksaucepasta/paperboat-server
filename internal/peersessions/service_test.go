package peersessions

import (
	"context"
	"crypto/ed25519"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/mint"
)

type repositoryFunc func(context.Context, Request, [32]byte, reservation) (reservation, error)

func (f repositoryFunc) Reserve(ctx context.Context, request Request, hash [32]byte, value reservation) (reservation, error) {
	return f(ctx, request, hash, value)
}

type waitingRepository struct {
	mu        sync.Mutex
	available bool
	value     reservation
}

func (r *waitingRepository) Reserve(_ context.Context, _ Request, _ [32]byte, value reservation) (reservation, error) {
	value.UserID, value.HostGeneration = "user_1", 1
	value.Controlling.EndpointID, value.Controlling.PeerEndpointID = "endpoint_cli", "endpoint_machine"
	value.Controlled.EndpointID, value.Controlled.PeerEndpointID = "endpoint_machine", "endpoint_cli"
	value.EdgeNodeID, value.EdgePool = "edge_1", "development"
	value.SignalingHost, value.STUNHost, value.STUNPort = "signal.example.test", "stun.example.test", 3478
	r.mu.Lock()
	r.available, r.value = true, value
	r.mu.Unlock()
	return value, nil
}

func (r *waitingRepository) Controlled(_ context.Context, userID, machineID string, generation int64, _ time.Time) (reservation, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.available || userID != r.value.UserID || machineID != r.value.Controlled.EndpointID || generation != r.value.HostGeneration {
		return reservation{}, ErrUnavailable
	}
	r.available = false
	return r.value, nil
}

func TestWaitNextControlledWakesOnIssueAndCancels(t *testing.T) {
	provider, _ := mint.New([]mint.Key{{ID: "peer-test", PrivateKey: ed25519.NewKeyFromSeed([]byte(strings.Repeat("w", ed25519.SeedSize)))}}, "peer-test", time.Minute)
	repository := &waitingRepository{}
	service, _ := New(repository, provider, "https://api.example.test")
	result := make(chan Pair, 1)
	errs := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	go func() {
		pair, err := service.WaitNextControlled(ctx, "user_1", "endpoint_machine", 1)
		if err != nil {
			errs <- err
			return
		}
		result <- pair
	}()
	request := validRequestFixture()
	if _, err := service.Issue(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	select {
	case pair := <-result:
		if pair.Controlled.EndpointID != "endpoint_machine" {
			t.Fatalf("pair=%+v", pair)
		}
	case err := <-errs:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal("waiter was not notified")
	}

	canceled, stop := context.WithCancel(context.Background())
	stop()
	if _, err := service.WaitNextControlled(canceled, "user_1", "endpoint_machine", 1); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error=%v", err)
	}
}

func TestIssueMintsReciprocalRoleBoundPair(t *testing.T) {
	now := time.Unix(2000, 0).UTC()
	provider, err := mint.New([]mint.Key{{ID: "peer-test", PrivateKey: ed25519.NewKeyFromSeed([]byte(strings.Repeat("p", ed25519.SeedSize)))}}, "peer-test", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	repository := repositoryFunc(func(_ context.Context, request Request, _ [32]byte, value reservation) (reservation, error) {
		if request.AttemptGeneration != 2 || request.NetworkGeneration != 4 || request.RelayLatency == nil || request.RelayLatency.Generation != 7 {
			t.Fatalf("request = %+v", request)
		}
		value.Controlling.EndpointID, value.Controlling.PeerEndpointID = "endpoint_cli", "endpoint_machine"
		value.Controlled.EndpointID, value.Controlled.PeerEndpointID = "endpoint_machine", "endpoint_cli"
		value.EdgeNodeID, value.EdgePool = "edge_1", "development"
		value.SignalingHost, value.STUNHost, value.STUNPort = "signal.example.test", "stun.example.test", 3478
		value.ControllingCertificate, value.ControlledCertificate = []byte("cli-certificate"), []byte("machine-certificate")
		return value, nil
	})
	service, err := New(repository, provider, "https://api.example.test")
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return now }
	sequence := 0
	service.newID = func(prefix string) (string, error) {
		sequence++
		return prefix + "_0123456789abcdef" + string(rune('0'+sequence)), nil
	}
	request := validRequestFixture()
	request.RelayLatency = &RelayLatencyVector{Generation: 7, ObservedAt: now, Samples: []RelayLatencySample{{Region: "fsn1", RTTMS: 20}}}
	pair, err := service.Issue(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if !validICECredential(pair.ICEUfrag, 4) || !validICECredential(pair.ICEPassword, 22) {
		t.Fatalf("invalid ICE credentials: ufrag=%q password=%q", pair.ICEUfrag, pair.ICEPassword)
	}
	if pair.IntentID == "" || pair.Purpose != "interactive" || !pair.ExpiresAt.Equal(now.Add(5*time.Minute)) || pair.Controlling.EndpointID != "endpoint_cli" || pair.Controlled.EndpointID != "endpoint_machine" {
		t.Fatalf("pair = %+v", pair)
	}
	for _, credential := range []Credential{pair.Controlling, pair.Controlled} {
		claims, err := provider.VerifyCredential(credential.Token, "https://api.example.test", "peer_signaling", now)
		if err != nil {
			t.Fatal(err)
		}
		peer := "endpoint_machine"
		if credential.Role == "controlled" {
			peer = "endpoint_cli"
		}
		if claims.IntentID != pair.IntentID || claims.EndpointID != credential.EndpointID || claims.PeerEndpointID != peer || claims.PeerRole != credential.Role || claims.EdgeNodeID != pair.EdgeNodeID || claims.AttemptGeneration != 2 || claims.NetworkGeneration != 4 {
			t.Fatalf("claims = %+v", claims)
		}
	}
	relayClaims, err := provider.VerifyCredential(pair.Relay.Token, "https://api.example.test", "peer_relay", now)
	if err != nil {
		t.Fatal(err)
	}
	if pair.Relay.Region != pair.EdgePool || pair.Relay.RouteGeneration != 1 || pair.Relay.ByteLimit != relayByteLimit || relayClaims.Subject != pair.IntentID || relayClaims.RouteAllocation != pair.Relay.RouteAllocation || relayClaims.InitiatorEndpointID != pair.Controlling.EndpointID || relayClaims.ResponderEndpointID != pair.Controlled.EndpointID || relayClaims.EdgeNodeID != pair.EdgeNodeID {
		t.Fatalf("relay=%+v claims=%+v", pair.Relay, relayClaims)
	}
	pmtuClaims, err := provider.VerifyCredential(pair.Relay.PMTUToken, "https://api.example.test", "peer_pmtu", now)
	if err != nil {
		t.Fatal(err)
	}
	if pmtuClaims.RouteAllocation != pair.Relay.RouteAllocation || pmtuClaims.EdgeNodeID != pair.EdgeNodeID || len(pmtuClaims.RelayCarriers) != 0 {
		t.Fatalf("PMTU claims=%+v", pmtuClaims)
	}
	if len(pair.Relay.PMTUToken) > 1200-26-32 {
		t.Fatalf("PMTU credential length=%d does not fit minimum probe", len(pair.Relay.PMTUToken))
	}
}

func TestIssueRejectsStaleOrMalformedRelayLatency(t *testing.T) {
	now := time.Unix(2000, 0).UTC()
	provider, _ := mint.New([]mint.Key{{ID: "peer-test", PrivateKey: ed25519.NewKeyFromSeed([]byte(strings.Repeat("v", ed25519.SeedSize)))}}, "peer-test", time.Minute)
	called := false
	service, _ := New(repositoryFunc(func(context.Context, Request, [32]byte, reservation) (reservation, error) {
		called = true
		return reservation{}, nil
	}), provider, "https://api.example.test")
	service.now = func() time.Time { return now }
	for _, vector := range []RelayLatencyVector{
		{Generation: 1, ObservedAt: now.Add(-6 * time.Minute), Samples: []RelayLatencySample{{Region: "fsn1", RTTMS: 20}}},
		{Generation: 1, ObservedAt: now, Samples: []RelayLatencySample{{Region: "FSN1", RTTMS: 20}}},
	} {
		request := validRequestFixture()
		request.RelayLatency = &vector
		if _, err := service.Issue(context.Background(), request); !errors.Is(err, ErrInvalid) {
			t.Fatalf("vector=%#v err=%v", vector, err)
		}
	}
	if called {
		t.Fatal("invalid vector reached repository")
	}
}

func TestRandomICECredentialUsesICEAlphabet(t *testing.T) {
	for range 1_000 {
		ufrag, err := randomICECredential(24)
		if err != nil {
			t.Fatal(err)
		}
		password, err := randomICECredential(32)
		if err != nil {
			t.Fatal(err)
		}
		if !validICECredential(ufrag, 4) || !validICECredential(password, 22) {
			t.Fatalf("invalid generated ICE credentials: ufrag=%q password=%q", ufrag, password)
		}
	}
}

func TestIssueRejectsInvalidGeneratedICECredentialBeforePersistence(t *testing.T) {
	called := false
	repository := repositoryFunc(func(context.Context, Request, [32]byte, reservation) (reservation, error) {
		called = true
		return reservation{}, nil
	})
	provider, _ := mint.New([]mint.Key{{ID: "peer-test", PrivateKey: ed25519.NewKeyFromSeed([]byte(strings.Repeat("i", ed25519.SeedSize)))}}, "peer-test", time.Minute)
	service, _ := New(repository, provider, "https://api.example.test")
	service.newICE = func(int) (string, error) { return "invalid_ice_credential", nil }

	if _, err := service.Issue(context.Background(), validRequestFixture()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("error = %v", err)
	}
	if called {
		t.Fatal("invalid generated ICE credential reached persistence")
	}
}

func TestIssueRejectsInvalidRequestsBeforePersistence(t *testing.T) {
	called := false
	repository := repositoryFunc(func(context.Context, Request, [32]byte, reservation) (reservation, error) {
		called = true
		return reservation{}, nil
	})
	provider, _ := mint.New([]mint.Key{{ID: "peer-test", PrivateKey: ed25519.NewKeyFromSeed([]byte(strings.Repeat("q", ed25519.SeedSize)))}}, "peer-test", time.Minute)
	service, _ := New(repository, provider, "https://api.example.test")
	for _, mutate := range []func(*Request){
		func(value *Request) { value.OperationKey = "short" },
		func(value *Request) { value.OperationKey = "peer-operation-with\nnewline" },
		func(value *Request) {
			value.ControllingCertificateFingerprint = value.ControllingCertificateFingerprint[:31]
		},
		func(value *Request) {
			value.ControlledCertificateFingerprint = append([]byte(nil), value.ControllingCertificateFingerprint...)
		},
		func(value *Request) { value.AttemptGeneration = 0 },
		func(value *Request) { value.NetworkGeneration = 0 },
		func(value *Request) { value.Purpose = "terminal" },
		func(value *Request) { value.AllowedPaths = []string{"relay_wss", "direct_quic"} },
		func(value *Request) { value.AllowedPaths = []string{"relay_wss", "relay_wss"} },
	} {
		request := validRequestFixture()
		mutate(&request)
		if _, err := service.Issue(context.Background(), request); !errors.Is(err, ErrInvalid) {
			t.Fatalf("error = %v", err)
		}
	}
	if called {
		t.Fatal("invalid request reached persistence")
	}
}

func TestIssuePreservesExactRequestedPathPolicy(t *testing.T) {
	t.Parallel()
	for _, paths := range [][]string{{"direct_quic", "relay_quic", "relay_wss"}, {"direct_quic", "relay_quic"}, {"direct_quic"}, {"relay_quic", "relay_wss"}, {"relay_quic"}, {"relay_wss"}} {
		paths := paths
		repository := repositoryFunc(func(_ context.Context, _ Request, _ [32]byte, value reservation) (reservation, error) {
			value.Controlling.EndpointID, value.Controlling.PeerEndpointID = "endpoint_cli", "endpoint_machine"
			value.Controlled.EndpointID, value.Controlled.PeerEndpointID = "endpoint_machine", "endpoint_cli"
			value.EdgeNodeID, value.EdgePool = "edge_1", "development"
			value.SignalingHost, value.STUNHost, value.STUNPort = "signal.example.test", "stun.example.test", 3478
			return value, nil
		})
		provider, _ := mint.New([]mint.Key{{ID: "peer-test", PrivateKey: ed25519.NewKeyFromSeed([]byte(strings.Repeat("p", ed25519.SeedSize)))}}, "peer-test", time.Minute)
		service, _ := New(repository, provider, "https://api.example.test")
		request := validRequestFixture()
		request.AllowedPaths = paths
		pair, err := service.Issue(context.Background(), request)
		if err != nil || !slices.Equal(pair.AllowedPaths, paths) {
			t.Fatalf("paths=%v pair=%v err=%v", paths, pair.AllowedPaths, err)
		}
	}
}

func TestIssueRequiresExactTransferBindingForFileTransferKeyPurpose(t *testing.T) {
	now := time.Unix(2000, 0).UTC()
	var persisted reservation
	repository := repositoryFunc(func(_ context.Context, _ Request, _ [32]byte, value reservation) (reservation, error) {
		persisted = value
		value.Controlling.EndpointID, value.Controlling.PeerEndpointID = "endpoint_cli", "endpoint_machine"
		value.Controlled.EndpointID, value.Controlled.PeerEndpointID = "endpoint_machine", "endpoint_cli"
		value.EdgeNodeID, value.EdgePool = "edge_1", "development"
		value.SignalingHost, value.STUNHost, value.STUNPort = "signal.example.test", "stun.example.test", 3478
		return value, nil
	})
	provider, _ := mint.New([]mint.Key{{ID: "peer-test", PrivateKey: ed25519.NewKeyFromSeed([]byte(strings.Repeat("k", ed25519.SeedSize)))}}, "peer-test", time.Minute)
	service, _ := New(repository, provider, "https://api.example.test")
	service.now = func() time.Time { return now }

	request := validRequestFixture()
	request.Purpose = "file_transfer_key"
	request.Consumer = "file_transfer_key"
	if _, err := service.Issue(context.Background(), request); !errors.Is(err, ErrInvalid) {
		t.Fatalf("missing binding err=%v", err)
	}
	request.Transfer = &TransferBinding{TransferID: "transfer_01", Generation: 2, ExpiresAt: now.Add(time.Hour)}
	pair, err := service.Issue(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if pair.Transfer == request.Transfer || pair.Transfer == nil || *pair.Transfer != *request.Transfer || persisted.Transfer == request.Transfer {
		t.Fatal("transfer binding was not preserved through independent copies")
	}
	request.Purpose = "interactive"
	request.Consumer = "terminal"
	if _, err := service.Issue(context.Background(), request); !errors.Is(err, ErrInvalid) {
		t.Fatalf("interactive binding err=%v", err)
	}
}

func TestIssueAcceptsBoundedApplicationPurposesWithoutTransferBinding(t *testing.T) {
	repository := repositoryFunc(func(_ context.Context, _ Request, _ [32]byte, value reservation) (reservation, error) {
		value.Controlling.EndpointID, value.Controlling.PeerEndpointID = "endpoint_cli", "endpoint_machine"
		value.Controlled.EndpointID, value.Controlled.PeerEndpointID = "endpoint_machine", "endpoint_cli"
		value.EdgeNodeID, value.EdgePool = "edge_1", "development"
		value.SignalingHost, value.STUNHost, value.STUNPort = "signal.example.test", "stun.example.test", 3478
		return value, nil
	})
	provider, _ := mint.New([]mint.Key{{ID: "peer-test", PrivateKey: ed25519.NewKeyFromSeed([]byte(strings.Repeat("k", ed25519.SeedSize)))}}, "peer-test", time.Minute)
	service, _ := New(repository, provider, "https://api.example.test")
	service.now = func() time.Time { return time.Unix(2000, 0).UTC() }
	for _, purpose := range []string{"peer_transport", "private_preview", "codex"} {
		request := validRequestFixture()
		request.Purpose = purpose
		request.Consumer = purpose
		request.OperationKey += "-" + purpose
		pair, err := service.Issue(context.Background(), request)
		if err != nil {
			t.Fatal(err)
		}
		if pair.Purpose != purpose || pair.Transfer != nil {
			t.Fatalf("pair purpose=%q transfer=%v", pair.Purpose, pair.Transfer)
		}
	}
}

func TestPeerTransportPurposeRequiresExactGenericConsumer(t *testing.T) {
	for _, consumer := range []string{"terminal", "exec", "ssh", "private_preview", "codex", ""} {
		if validPurposeConsumer("peer_transport", consumer) {
			t.Fatalf("consumer=%q was accepted", consumer)
		}
	}
	if !validPurposeConsumer("peer_transport", "peer_transport") || validPurposeConsumer("interactive", "peer_transport") {
		t.Fatal("generic transport consumer boundary is inconsistent")
	}
}

func TestIssueReplayReturnsOriginalICECredentials(t *testing.T) {
	var stored reservation
	repository := repositoryFunc(func(_ context.Context, _ Request, _ [32]byte, proposed reservation) (reservation, error) {
		if stored.IntentID != "" {
			return stored, nil
		}
		proposed.EdgeNodeID, proposed.EdgePool = "edge_1", "development"
		proposed.SignalingHost, proposed.STUNHost, proposed.STUNPort = "signal.example.test", "stun.example.test", 3478
		proposed.Controlling.EndpointID, proposed.Controlling.PeerEndpointID = "endpoint_cli", "endpoint_machine"
		proposed.Controlled.EndpointID, proposed.Controlled.PeerEndpointID = "endpoint_machine", "endpoint_cli"
		stored = proposed
		return proposed, nil
	})
	provider, _ := mint.New([]mint.Key{{ID: "peer-test", PrivateKey: ed25519.NewKeyFromSeed([]byte(strings.Repeat("r", ed25519.SeedSize)))}}, "peer-test", time.Minute)
	service, _ := New(repository, provider, "https://api.example.test")
	first, err := service.Issue(context.Background(), validRequestFixture())
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.Issue(context.Background(), validRequestFixture())
	if err != nil || first.IntentID != second.IntentID || first.ICEUfrag != second.ICEUfrag || first.ICEPassword != second.ICEPassword || first.Relay.RouteAllocation != second.Relay.RouteAllocation || first.Relay.Token != second.Relay.Token {
		t.Fatalf("first=%+v second=%+v err=%v", first, second, err)
	}
	if len(first.ICEUfrag) < 16 || len(first.ICEPassword) < 32 || first.ICEUfrag == first.ICEPassword {
		t.Fatalf("invalid ICE credentials: %q %q", first.ICEUfrag, first.ICEPassword)
	}
}

func validRequestFixture() Request {
	return Request{OperationKey: "peer-operation-0123456789", UserID: "user_1", CLIClientSessionID: "cli_1", EnvironmentID: "env_1", Purpose: "interactive", Consumer: "terminal", ControllingCertificateFingerprint: bytesOf(1), ControlledCertificateFingerprint: bytesOf(2), AttemptGeneration: 2, NetworkGeneration: 4}
}

func bytesOf(value byte) []byte { return []byte(strings.Repeat(string(rune(value)), 32)) }
