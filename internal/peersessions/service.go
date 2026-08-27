// Package peersessions owns durable peer-session intent and paired signaling authority.
package peersessions

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/mint"
)

const (
	intentTTL      = 5 * time.Minute
	relayByteLimit = int64(1 << 30)
)

var (
	ErrInvalid     = errors.New("peer session request is invalid")
	ErrConflict    = errors.New("peer session operation conflicts with its original request")
	ErrUnavailable = errors.New("peer session authority is unavailable")
)

type Signer interface {
	SignCredential(mint.CredentialInput) (string, error)
}

type Request struct {
	OperationKey                      string
	UserID                            string
	CLIClientSessionID                string
	EnvironmentID                     string
	Purpose                           string
	Consumer                          string
	ControllingCertificateFingerprint []byte
	ControlledCertificateFingerprint  []byte
	AttemptGeneration                 int64
	NetworkGeneration                 int64
	AllowedPaths                      []string
	Transfer                          *TransferBinding
	RelayLatency                      *RelayLatencyVector
}

type RelayLatencySample struct {
	Region string `json:"region"`
	RTTMS  int64  `json:"rtt_ms"`
}

type RelayLatencyVector struct {
	Generation         uint64               `json:"generation"`
	ObservedAt         time.Time            `json:"observed_at"`
	Samples            []RelayLatencySample `json:"samples"`
	RelaySuccessRegion string               `json:"relay_success_region,omitempty"`
	RelaySuccessAt     time.Time            `json:"relay_success_at,omitempty"`
}

type TransferBinding struct {
	TransferID string    `json:"transfer_id"`
	Generation int64     `json:"generation"`
	ExpiresAt  time.Time `json:"expires_at"`
}

type Credential struct {
	EndpointID string
	Role       string
	Token      string
	ExpiresAt  time.Time
}

// TrustedKey is an active account E2EE key that a peer can use to validate
// endpoint certificates carried by a session descriptor.
type TrustedKey struct {
	KeyID       string
	PublicKey   []byte
	Fingerprint []byte
	Generation  int64
}

type Relay struct {
	Region          string
	RouteAllocation string
	RouteGeneration int64
	Token           string
	PMTUToken       string
	ByteLimit       int64
	ExpiresAt       time.Time
}

type Pair struct {
	UserID                      string
	CLIClientSessionID          string
	OperationKey                string
	IntentID                    string
	EnvironmentID               string
	Purpose                     string
	Consumer                    string
	EdgeNodeID                  string
	EdgePool                    string
	SignalingHost               string
	STUNHost                    string
	STUNPort                    uint16
	ICEUfrag                    string
	ICEPassword                 string
	ControllingCertificate      []byte
	ControlledCertificate       []byte
	ControllingCertificateKeyID string
	ControlledCertificateKeyID  string
	TrustedKeys                 []TrustedKey
	AttemptGeneration           int64
	NetworkGeneration           int64
	AllowedPaths                []string
	HostGeneration              int64
	AuthorizationGeneration     int64
	IssuedAt                    time.Time
	ExpiresAt                   time.Time
	Controlling                 Credential
	Controlled                  Credential
	Relay                       Relay
	Transfer                    *TransferBinding
}

type reservation struct {
	UserID                      string
	CLIClientSessionID          string
	OperationKey                string
	IntentID                    string
	EnvironmentID               string
	Purpose                     string
	Consumer                    string
	EdgeNodeID                  string
	AttemptGeneration           int64
	NetworkGeneration           int64
	AllowedPaths                []string
	HostGeneration              int64
	AuthorizationGeneration     int64
	EdgePool                    string
	SignalingHost               string
	STUNHost                    string
	STUNPort                    uint16
	ICEUfrag                    string
	ICEPassword                 string
	ControllingCertificate      []byte
	ControlledCertificate       []byte
	ControllingCertificateKeyID string
	ControlledCertificateKeyID  string
	TrustedKeys                 []TrustedKey
	IssuedAt                    time.Time
	ExpiresAt                   time.Time
	Controlling                 grant
	Controlled                  grant
	Relay                       relayAllocation
	Transfer                    *TransferBinding
}

type grant struct {
	EndpointID     string
	PeerEndpointID string
	Role           string
	JTI            string
}

type relayAllocation struct {
	RouteAllocation string
	JTI             string
	RouteGeneration int64
	ByteLimit       int64
}

type Repository interface {
	Reserve(context.Context, Request, [32]byte, reservation) (reservation, error)
}

type Service struct {
	repository Repository
	signer     Signer
	issuer     string
	now        func() time.Time
	newID      func(string) (string, error)
	newSecret  func(int) (string, error)
	newICE     func(int) (string, error)
	waitMu     sync.Mutex
	waiters    map[string]map[chan struct{}]struct{}
}

type revocationRepository interface {
	Revoke(context.Context, string, string, string, int64, string, time.Time) error
}

type controlledRepository interface {
	Controlled(context.Context, string, string, int64, time.Time) (reservation, error)
}

type expiryRepository interface {
	Expire(context.Context, time.Time) error
}

func New(repository Repository, signer Signer, issuer string) (*Service, error) {
	if repository == nil || signer == nil || issuer == "" {
		return nil, ErrInvalid
	}
	return &Service{repository: repository, signer: signer, issuer: issuer, now: time.Now, newID: randomID, newSecret: randomSecret, newICE: randomICECredential, waiters: make(map[string]map[chan struct{}]struct{})}, nil
}

// ExpiryWorker keeps durable peer-session credentials from remaining visible
// to controlled runtimes after their five-minute authority lifetime.
func (s *Service) ExpiryWorker(interval time.Duration) func(context.Context) error {
	if interval <= 0 {
		interval = time.Minute
	}
	repository, ok := s.repository.(expiryRepository)
	if !ok {
		return func(context.Context) error { return ErrInvalid }
	}
	return func(ctx context.Context) error {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			if err := repository.Expire(ctx, time.Now().UTC()); err != nil && !errors.Is(err, context.Canceled) {
				return err
			}
			select {
			case <-ticker.C:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
}

func (s *Service) Issue(ctx context.Context, request Request) (Pair, error) {
	request.AllowedPaths = normalizedAllowedPaths(request.Purpose, request.AllowedPaths)
	if s == nil || ctx == nil || !validRequest(request) {
		return Pair{}, ErrInvalid
	}
	now := s.now().UTC()
	if request.RelayLatency != nil && !validRelayLatency(*request.RelayLatency, now) {
		return Pair{}, ErrInvalid
	}
	if request.Transfer != nil && (!request.Transfer.ExpiresAt.After(now) || request.Transfer.ExpiresAt.After(now.Add(8*24*time.Hour))) {
		return Pair{}, ErrInvalid
	}
	intentID, err := s.newID("psi")
	if err != nil {
		return Pair{}, err
	}
	controllingJTI, err := s.newID("jti_peer_signal")
	if err != nil {
		return Pair{}, err
	}
	controlledJTI, err := s.newID("jti_peer_signal")
	if err != nil {
		return Pair{}, err
	}
	relayJTI, err := s.newID("jti_peer_relay")
	if err != nil {
		return Pair{}, err
	}
	routeAllocation, err := s.newSecret(16)
	if err != nil {
		return Pair{}, err
	}
	iceUfrag, err := s.newICE(24)
	if err != nil {
		return Pair{}, err
	}
	if !validICECredential(iceUfrag, 4) {
		return Pair{}, ErrInvalid
	}
	icePassword, err := s.newICE(32)
	if err != nil {
		return Pair{}, err
	}
	if !validICECredential(icePassword, 22) {
		return Pair{}, ErrInvalid
	}
	reserved, err := s.repository.Reserve(ctx, request, requestHash(request), reservation{
		IntentID: intentID, UserID: request.UserID, CLIClientSessionID: request.CLIClientSessionID, OperationKey: request.OperationKey, EnvironmentID: request.EnvironmentID, Purpose: request.Purpose, Consumer: request.Consumer,
		AttemptGeneration: request.AttemptGeneration, NetworkGeneration: request.NetworkGeneration,
		AllowedPaths: append([]string(nil), request.AllowedPaths...),
		ICEUfrag:     iceUfrag, ICEPassword: icePassword,
		IssuedAt: now, ExpiresAt: now.Add(intentTTL),
		Controlling: grant{Role: "controlling", JTI: controllingJTI},
		Controlled:  grant{Role: "controlled", JTI: controlledJTI},
		Relay:       relayAllocation{RouteAllocation: routeAllocation, JTI: relayJTI, RouteGeneration: 1, ByteLimit: relayByteLimit},
		Transfer:    cloneTransferBinding(request.Transfer),
	})
	if err != nil {
		return Pair{}, err
	}
	s.notifyControlled(reserved.UserID, reserved.Controlled.EndpointID, reserved.HostGeneration)
	controlling, err := s.sign(reserved, reserved.Controlling)
	if err != nil {
		return Pair{}, err
	}
	controlled, err := s.sign(reserved, reserved.Controlled)
	if err != nil {
		return Pair{}, err
	}
	relay, err := s.signRelay(reserved)
	if err != nil {
		return Pair{}, err
	}
	return pairFromReservation(reserved, controlling, controlled, relay), nil
}

// WaitNextControlled keeps the machine's daemon-wide control request parked
// until authority is available. The second read after subscribing closes the
// issue/subscribe race; the bounded refresh also covers multi-instance issue
// delivery without returning to client-side polling.
func (s *Service) WaitNextControlled(ctx context.Context, userID, machineID string, hostGeneration int64) (Pair, error) {
	if s == nil || ctx == nil {
		return Pair{}, ErrInvalid
	}
	for {
		pair, err := s.NextControlled(ctx, userID, machineID, hostGeneration)
		if !errors.Is(err, ErrUnavailable) {
			return pair, err
		}
		ready, unsubscribe := s.subscribeControlled(userID, machineID, hostGeneration)
		pair, err = s.NextControlled(ctx, userID, machineID, hostGeneration)
		if !errors.Is(err, ErrUnavailable) {
			unsubscribe()
			return pair, err
		}
		timer := time.NewTimer(250 * time.Millisecond)
		select {
		case <-ready:
		case <-timer.C:
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			unsubscribe()
			return Pair{}, ctx.Err()
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		unsubscribe()
	}
}

func controlledWaitKey(userID, machineID string, hostGeneration int64) string {
	return userID + "\x00" + machineID + "\x00" + fmt.Sprint(hostGeneration)
}

func (s *Service) subscribeControlled(userID, machineID string, hostGeneration int64) (<-chan struct{}, func()) {
	key := controlledWaitKey(userID, machineID, hostGeneration)
	ready := make(chan struct{})
	s.waitMu.Lock()
	if s.waiters[key] == nil {
		s.waiters[key] = make(map[chan struct{}]struct{})
	}
	s.waiters[key][ready] = struct{}{}
	s.waitMu.Unlock()
	var once sync.Once
	return ready, func() {
		once.Do(func() {
			s.waitMu.Lock()
			delete(s.waiters[key], ready)
			if len(s.waiters[key]) == 0 {
				delete(s.waiters, key)
			}
			s.waitMu.Unlock()
		})
	}
}

func (s *Service) notifyControlled(userID, machineID string, hostGeneration int64) {
	key := controlledWaitKey(userID, machineID, hostGeneration)
	s.waitMu.Lock()
	waiters := s.waiters[key]
	delete(s.waiters, key)
	for ready := range waiters {
		close(ready)
	}
	s.waitMu.Unlock()
}

func (s *Service) NextControlled(ctx context.Context, userID, machineID string, hostGeneration int64) (Pair, error) {
	if s == nil || ctx == nil || !bounded(userID, 1, 256) || !bounded(machineID, 1, 128) || hostGeneration <= 0 {
		return Pair{}, ErrInvalid
	}
	repository, ok := s.repository.(controlledRepository)
	if !ok {
		return Pair{}, ErrUnavailable
	}
	reserved, err := repository.Controlled(ctx, userID, machineID, hostGeneration, s.now().UTC())
	if err != nil {
		return Pair{}, err
	}
	controlling, err := s.sign(reserved, reserved.Controlling)
	if err != nil {
		return Pair{}, err
	}
	controlled, err := s.sign(reserved, reserved.Controlled)
	if err != nil {
		return Pair{}, err
	}
	relay, err := s.signRelay(reserved)
	if err != nil {
		return Pair{}, err
	}
	return pairFromReservation(reserved, controlling, controlled, relay), nil
}

func pairFromReservation(value reservation, controlling, controlled Credential, relay Relay) Pair {
	trustedKeys := make([]TrustedKey, 0, len(value.TrustedKeys))
	for _, key := range value.TrustedKeys {
		trustedKeys = append(trustedKeys, TrustedKey{KeyID: key.KeyID, PublicKey: append([]byte(nil), key.PublicKey...), Fingerprint: append([]byte(nil), key.Fingerprint...), Generation: key.Generation})
	}
	return Pair{UserID: value.UserID, CLIClientSessionID: value.CLIClientSessionID, OperationKey: value.OperationKey, IntentID: value.IntentID, EnvironmentID: value.EnvironmentID, Purpose: value.Purpose, Consumer: value.Consumer, EdgeNodeID: value.EdgeNodeID, EdgePool: value.EdgePool, SignalingHost: value.SignalingHost, STUNHost: value.STUNHost, STUNPort: value.STUNPort, ICEUfrag: value.ICEUfrag, ICEPassword: value.ICEPassword, ControllingCertificate: append([]byte(nil), value.ControllingCertificate...), ControlledCertificate: append([]byte(nil), value.ControlledCertificate...), ControllingCertificateKeyID: value.ControllingCertificateKeyID, ControlledCertificateKeyID: value.ControlledCertificateKeyID, TrustedKeys: trustedKeys, AttemptGeneration: value.AttemptGeneration, NetworkGeneration: value.NetworkGeneration, AllowedPaths: append([]string(nil), value.AllowedPaths...), HostGeneration: value.HostGeneration, AuthorizationGeneration: value.AuthorizationGeneration, IssuedAt: value.IssuedAt, ExpiresAt: value.ExpiresAt, Controlling: controlling, Controlled: controlled, Relay: relay, Transfer: cloneTransferBinding(value.Transfer)}
}

func (s *Service) signRelay(intent reservation) (Relay, error) {
	token, err := s.signer.SignCredential(mint.CredentialInput{
		Issuer: s.issuer, Audience: "paperboat-edge", Subject: intent.IntentID, JTI: intent.Relay.JTI,
		IssuedAt: intent.IssuedAt, ExpiresAt: intent.ExpiresAt, CredentialClass: "peer_relay",
		Scopes: []string{"peer:relay"}, EnvironmentID: intent.EnvironmentID, IntentID: intent.IntentID,
		EdgeNodeID: intent.EdgeNodeID, RouteAllocation: intent.Relay.RouteAllocation,
		InitiatorEndpointID: intent.Controlling.EndpointID, ResponderEndpointID: intent.Controlled.EndpointID,
		AttemptGeneration: intent.AttemptGeneration, NetworkGeneration: intent.NetworkGeneration,
		RouteGeneration: intent.Relay.RouteGeneration, RelayByteLimit: intent.Relay.ByteLimit,
		RelayCarriers: []string{"relay_quic", "relay_wss"},
	})
	if err != nil {
		return Relay{}, err
	}
	pmtuToken, err := s.signer.SignCredential(mint.CredentialInput{
		Issuer: s.issuer, Audience: "paperboat-edge", Subject: intent.IntentID, JTI: intent.Relay.JTI,
		IssuedAt: intent.IssuedAt, ExpiresAt: intent.ExpiresAt, CredentialClass: "peer_pmtu",
		Scopes: []string{"peer:pmtu"}, EnvironmentID: intent.EnvironmentID, IntentID: intent.IntentID,
		EdgeNodeID: intent.EdgeNodeID, RouteAllocation: intent.Relay.RouteAllocation,
		InitiatorEndpointID: intent.Controlling.EndpointID, ResponderEndpointID: intent.Controlled.EndpointID,
		AttemptGeneration: intent.AttemptGeneration, NetworkGeneration: intent.NetworkGeneration,
		RouteGeneration: intent.Relay.RouteGeneration, RelayByteLimit: intent.Relay.ByteLimit,
	})
	if err != nil {
		return Relay{}, err
	}
	return Relay{Region: intent.EdgePool, RouteAllocation: intent.Relay.RouteAllocation, RouteGeneration: intent.Relay.RouteGeneration, Token: token, PMTUToken: pmtuToken, ByteLimit: intent.Relay.ByteLimit, ExpiresAt: intent.ExpiresAt}, nil
}

func (s *Service) Revoke(ctx context.Context, actorUserID, operationKey, intentID string, attemptGeneration int64, reason string) error {
	if s == nil || ctx == nil || !bounded(actorUserID, 1, 256) || !bounded(operationKey, 16, 256) || !bounded(intentID, 1, 132) || attemptGeneration <= 0 || !validRevocationReason(reason) {
		return ErrInvalid
	}
	repository, ok := s.repository.(revocationRepository)
	if !ok {
		return ErrUnavailable
	}
	return repository.Revoke(ctx, actorUserID, operationKey, intentID, attemptGeneration, reason, s.now().UTC())
}

func (s *Service) sign(intent reservation, value grant) (Credential, error) {
	token, err := s.signer.SignCredential(mint.CredentialInput{
		Issuer: s.issuer, Audience: "paperboat-edge", Subject: value.EndpointID, JTI: value.JTI,
		IssuedAt: intent.IssuedAt, ExpiresAt: intent.ExpiresAt, CredentialClass: "peer_signaling",
		Scopes: []string{"peer:signal"}, EnvironmentID: intent.EnvironmentID, IntentID: intent.IntentID,
		EndpointID: value.EndpointID, PeerEndpointID: value.PeerEndpointID,
		AttemptGeneration: intent.AttemptGeneration, NetworkGeneration: intent.NetworkGeneration,
		PeerRole: value.Role, EdgeNodeID: intent.EdgeNodeID,
	})
	if err != nil {
		return Credential{}, err
	}
	return Credential{EndpointID: value.EndpointID, Role: value.Role, Token: token, ExpiresAt: intent.ExpiresAt}, nil
}

func validRequest(value Request) bool {
	validPurpose := value.Purpose == "peer_transport" || value.Purpose == "interactive" || value.Purpose == "private_preview" || value.Purpose == "codex" || value.Purpose == "health_probe" || value.Purpose == "direct_probe" || value.Purpose == "file_transfer_key"
	validTransfer := validTransferBinding(value.Purpose, value.Transfer)
	return bounded(value.OperationKey, 16, 256) && bounded(value.UserID, 1, 256) && bounded(value.CLIClientSessionID, 1, 256) && bounded(value.EnvironmentID, 1, 256) && validPurpose && validPurposeConsumer(value.Purpose, value.Consumer) && validTransfer && validAllowedPaths(value.Purpose, value.AllowedPaths) && len(value.ControllingCertificateFingerprint) == sha256.Size && len(value.ControlledCertificateFingerprint) == sha256.Size && !equalBytes(value.ControllingCertificateFingerprint, value.ControlledCertificateFingerprint) && value.AttemptGeneration > 0 && value.NetworkGeneration > 0
}

func normalizedAllowedPaths(purpose string, paths []string) []string {
	if len(paths) > 0 {
		return append([]string(nil), paths...)
	}
	if purpose == "direct_probe" {
		return []string{"direct_quic"}
	}
	return []string{"direct_quic", "relay_quic", "relay_wss"}
}

func validAllowedPaths(purpose string, paths []string) bool {
	if purpose == "direct_probe" {
		return slices.Equal(paths, []string{"direct_quic"})
	}
	for _, allowed := range [][]string{{"direct_quic", "relay_quic", "relay_wss"}, {"direct_quic", "relay_quic"}, {"direct_quic"}, {"relay_quic", "relay_wss"}, {"relay_quic"}, {"relay_wss"}} {
		if slices.Equal(paths, allowed) {
			return true
		}
	}
	return false
}

func validPurposeConsumer(purpose, consumer string) bool {
	switch purpose {
	case "peer_transport":
		return consumer == "peer_transport"
	case "interactive":
		return consumer == "terminal" || consumer == "exec" || consumer == "ssh"
	case "private_preview", "codex", "health_probe", "file_transfer_key":
		return consumer == purpose
	case "direct_probe":
		return consumer == "terminal"
	default:
		return false
	}
}

func validTransferBinding(purpose string, value *TransferBinding) bool {
	if purpose != "file_transfer_key" {
		return value == nil
	}
	return value != nil && bounded(value.TransferID, 1, 128) && value.Generation > 0 && !value.ExpiresAt.IsZero() && value.ExpiresAt.Nanosecond() == 0
}

func validRelayLatency(value RelayLatencyVector, now time.Time) bool {
	if value.Generation == 0 || value.ObservedAt.IsZero() || value.ObservedAt.After(now.Add(30*time.Second)) || now.Sub(value.ObservedAt) > 5*time.Minute || len(value.Samples) == 0 || len(value.Samples) > 32 {
		return false
	}
	if value.RelaySuccessRegion == "" != value.RelaySuccessAt.IsZero() || value.RelaySuccessRegion != "" && (!validRelayRegion(value.RelaySuccessRegion) || value.RelaySuccessAt.After(value.ObservedAt) || value.ObservedAt.Sub(value.RelaySuccessAt) > 30*time.Second) {
		return false
	}
	seen := make(map[string]bool, len(value.Samples))
	for _, sample := range value.Samples {
		if !validRelayRegion(sample.Region) || sample.RTTMS < 1 || sample.RTTMS > 60_000 || seen[sample.Region] {
			return false
		}
		seen[sample.Region] = true
	}
	return true
}

func validRelayRegion(value string) bool {
	if value == "" || len(value) > 63 {
		return false
	}
	for _, r := range value {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			return false
		}
	}
	return value[0] != '-' && value[len(value)-1] != '-'
}

func cloneTransferBinding(value *TransferBinding) *TransferBinding {
	if value == nil {
		return nil
	}
	clone := *value
	clone.ExpiresAt = clone.ExpiresAt.UTC().Truncate(time.Second)
	return &clone
}

func bounded(value string, minimum, maximum int) bool {
	if len(value) < minimum || len(value) > maximum {
		return false
	}
	for _, character := range value {
		if character == 0 || character == '\r' || character == '\n' {
			return false
		}
	}
	return true
}

func requestHash(value Request) [32]byte {
	data, _ := json.Marshal(value)
	return sha256.Sum256(data)
}

func randomID(prefix string) (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return prefix + "_" + hex.EncodeToString(raw[:]), nil
}

func randomSecret(size int) (string, error) {
	if size < 16 || size > 128 {
		return "", ErrInvalid
	}
	raw := make([]byte, size)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func randomICECredential(size int) (string, error) {
	if size < 16 || size > 128 {
		return "", ErrInvalid
	}
	raw := make([]byte, size)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(raw), nil
}

func validICECredential(value string, minimum int) bool {
	if len(value) < minimum || len(value) > 256 {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '+' || character == '/' {
			continue
		}
		return false
	}
	return true
}

func equalBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var different byte
	for index := range left {
		different |= left[index] ^ right[index]
	}
	return different == 0
}
