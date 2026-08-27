package peeridentity

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"time"

	"golang.org/x/crypto/blake2s"
)

var (
	ErrConflict    = errors.New("endpoint certificate registration conflicts with current authority")
	ErrUnavailable = errors.New("endpoint certificate authority is unavailable")
)

type RegisterRequest struct {
	OperationID                    string
	UserID                         string
	KeyID                          string
	Certificate                    []byte
	Expected                       Expected
	ExpectedRootFingerprint        [sha256.Size]byte
	ExpectedCertificateFingerprint [sha256.Size]byte
	ExpectedIssuedAt               time.Time
	ExpectedExpiresAt              time.Time
	Now                            time.Time
}

type BootstrapRequest struct {
	RegisterRequest
	CLIClientSessionID   string
	RootPublicKey        ed25519.PublicKey
	AllowRootReplacement bool
}

type AccountRoot struct {
	Keys []AccountKey
}

type AccountKey struct {
	KeyID       string
	PublicKey   ed25519.PublicKey
	Fingerprint [sha256.Size]byte
	Generation  uint64
}

type EndpointEnrollmentRequest struct {
	ID             string
	UserID         string
	EndpointID     string
	Generation     uint64
	Role           Role
	State          string
	NoisePublicKey [32]byte
	QUICPublicKey  [32]byte
	CreatedAt      time.Time
	ExpiresAt      time.Time
}

func (r EndpointEnrollmentRequest) SafetyCode() string {
	buffer := make([]byte, 0, 64+len(r.EndpointID))
	domain := "paperboat-machine-endpoint-v1"
	if r.Role == RoleCLI {
		domain = "paperboat-cli-endpoint-v1"
	}
	buffer = append(buffer, domain...)
	buffer = append(buffer, 0)
	buffer = append(buffer, r.EndpointID...)
	buffer = append(buffer, 0)
	var generation [8]byte
	binary.BigEndian.PutUint64(generation[:], r.Generation)
	buffer = append(buffer, generation[:]...)
	buffer = append(buffer, r.NoisePublicKey[:]...)
	buffer = append(buffer, r.QUICPublicKey[:]...)
	digest := blake2s.Sum256(buffer)
	encoded := hex.EncodeToString(digest[:5])
	return encoded[:5] + "-" + encoded[5:]
}

type MachineEndpointRequest struct {
	OperationID    string
	UserID         string
	EndpointID     string
	Generation     uint64
	NoisePublicKey [32]byte
	QUICPublicKey  [32]byte
	Now            time.Time
}

type CLIEndpointRequest struct {
	OperationID    string
	UserID         string
	EndpointID     string
	Generation     uint64
	NoisePublicKey [32]byte
	QUICPublicKey  [32]byte
	Now            time.Time
}

func (s *Service) Root(ctx context.Context, userID string) (AccountRoot, error) {
	if s == nil || ctx == nil || !identifierExpr.MatchString(userID) {
		return AccountRoot{}, ErrInvalid
	}
	return s.repository.ResolveAccountRoot(ctx, userID)
}

type Repository interface {
	Bootstrap(context.Context, string, string, ed25519.PublicKey, Certificate) (Certificate, error)
	ResolveAccountRoot(context.Context, string) (AccountRoot, error)
	Register(context.Context, string, string, Certificate) (Certificate, error)
	Get(context.Context, string, string, uint64, time.Time) (Certificate, error)
	Revoke(context.Context, string, string, string, uint64, uint64, string, time.Time) (Certificate, error)
	RequestMachineEndpoint(context.Context, MachineEndpointRequest, string, [sha256.Size]byte, time.Time) (EndpointEnrollmentRequest, error)
	ListPendingEndpoints(context.Context, string, time.Time, int32) ([]EndpointEnrollmentRequest, error)
}

func (s *Service) RequestMachineEndpoint(ctx context.Context, request MachineEndpointRequest) (EndpointEnrollmentRequest, error) {
	if s == nil || ctx == nil || len(request.OperationID) < 8 || len(request.OperationID) > 128 || !identifierExpr.MatchString(request.UserID) || !identifierExpr.MatchString(request.EndpointID) || request.Generation == 0 || request.Generation > maximumInteger || request.Now.IsZero() || zeroKey(request.NoisePublicKey) || zeroKey(request.QUICPublicKey) {
		return EndpointEnrollmentRequest{}, ErrInvalid
	}
	id, err := randomEndpointRequestID()
	if err != nil {
		return EndpointEnrollmentRequest{}, err
	}
	hash := sha256.Sum256(append(append(append([]byte(request.UserID+"\x00"+request.EndpointID+"\x00"+request.OperationID+"\x00"), request.NoisePublicKey[:]...), request.QUICPublicKey[:]...), byte(request.Generation>>56), byte(request.Generation>>48), byte(request.Generation>>40), byte(request.Generation>>32), byte(request.Generation>>24), byte(request.Generation>>16), byte(request.Generation>>8), byte(request.Generation)))
	return s.repository.RequestMachineEndpoint(ctx, request, id, hash, request.Now.UTC().Add(5*time.Minute))
}

func (s *Service) RequestCLIEndpoint(ctx context.Context, request CLIEndpointRequest) (EndpointEnrollmentRequest, error) {
	if s == nil || ctx == nil || len(request.OperationID) < 8 || len(request.OperationID) > 128 || !identifierExpr.MatchString(request.UserID) || !identifierExpr.MatchString(request.EndpointID) || request.Generation != 1 || request.Now.IsZero() || zeroKey(request.NoisePublicKey) || zeroKey(request.QUICPublicKey) {
		return EndpointEnrollmentRequest{}, ErrInvalid
	}
	id, err := randomEndpointRequestID()
	if err != nil {
		return EndpointEnrollmentRequest{}, err
	}
	hash := sha256.Sum256(append(append(append([]byte(request.UserID+"\x00"+request.EndpointID+"\x00"+request.OperationID+"\x00cli\x00"), request.NoisePublicKey[:]...), request.QUICPublicKey[:]...), 0, 0, 0, 0, 0, 0, 0, 1))
	repository, ok := s.repository.(interface {
		RequestCLIEndpoint(context.Context, CLIEndpointRequest, string, [sha256.Size]byte, time.Time) (EndpointEnrollmentRequest, error)
	})
	if !ok {
		return EndpointEnrollmentRequest{}, ErrUnavailable
	}
	return repository.RequestCLIEndpoint(ctx, request, id, hash, request.Now.UTC().Add(5*time.Minute))
}

func (s *Service) PendingEndpoints(ctx context.Context, userID string, now time.Time) ([]EndpointEnrollmentRequest, error) {
	if s == nil || ctx == nil || !identifierExpr.MatchString(userID) || now.IsZero() {
		return nil, ErrInvalid
	}
	return s.repository.ListPendingEndpoints(ctx, userID, now.UTC(), 100)
}

func randomEndpointRequestID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return "per_" + hex.EncodeToString(raw[:]), nil
}

func zeroKey(value [32]byte) bool {
	var combined byte
	for _, item := range value {
		combined |= item
	}
	return combined == 0
}

func (s *Service) Bootstrap(ctx context.Context, request BootstrapRequest) (Certificate, error) {
	if s == nil || ctx == nil || !identifierExpr.MatchString(request.CLIClientSessionID) || request.Expected.Role != RoleCLI || request.Expected.EndpointID != request.CLIClientSessionID || len(request.RootPublicKey) != ed25519.PublicKeySize {
		return Certificate{}, ErrInvalid
	}
	rootFingerprint := sha256.Sum256(request.RootPublicKey)
	if request.ExpectedRootFingerprint != rootFingerprint || request.KeyID != keyIDForFingerprint(rootFingerprint) {
		return Certificate{}, ErrIdentity
	}
	certificate, err := validateRegistration(request.RegisterRequest, request.RootPublicKey)
	if err != nil {
		return Certificate{}, err
	}
	certificate.KeyID = keyIDForFingerprint(rootFingerprint)
	certificate.RootFingerprint = rootFingerprint
	if request.AllowRootReplacement {
		fresh, ok := s.repository.(interface {
			BootstrapFresh(context.Context, string, string, string, ed25519.PublicKey, Certificate) (Certificate, error)
		})
		if !ok {
			return Certificate{}, ErrUnavailable
		}
		return fresh.BootstrapFresh(ctx, request.OperationID, request.UserID, request.CLIClientSessionID, append(ed25519.PublicKey(nil), request.RootPublicKey...), certificate)
	}
	return s.repository.Bootstrap(ctx, request.OperationID, request.UserID, append(ed25519.PublicKey(nil), request.RootPublicKey...), certificate)
}

func (s *Service) Get(ctx context.Context, userID, endpointID string, generation uint64, now time.Time) (Certificate, error) {
	if s == nil || ctx == nil || !identifierExpr.MatchString(userID) || !identifierExpr.MatchString(endpointID) || generation == 0 || generation > maximumInteger || now.IsZero() {
		return Certificate{}, ErrInvalid
	}
	return s.repository.Get(ctx, userID, endpointID, generation, now.UTC())
}

func (s *Service) Revoke(ctx context.Context, operationID, userID, endpointID string, generation, serial uint64, reason string, now time.Time) (Certificate, error) {
	if s == nil || ctx == nil || len(operationID) < 16 || len(operationID) > 256 || !identifierExpr.MatchString(userID) ||
		!identifierExpr.MatchString(endpointID) || generation == 0 || generation > maximumInteger || serial == 0 || serial > maximumInteger ||
		(reason != "endpoint_removed" && reason != "key_compromise") || now.IsZero() {
		return Certificate{}, ErrInvalid
	}
	return s.repository.Revoke(ctx, operationID, userID, endpointID, generation, serial, reason, now.UTC())
}

type Service struct{ repository Repository }

func NewService(repository Repository) (*Service, error) {
	if nilRepository(repository) {
		return nil, ErrInvalid
	}
	return &Service{repository: repository}, nil
}

func (s *Service) Register(ctx context.Context, request RegisterRequest) (Certificate, error) {
	if s == nil || ctx == nil || len(request.OperationID) < 16 || len(request.OperationID) > 256 ||
		!identifierExpr.MatchString(request.UserID) || request.Expected.AccountID != request.UserID ||
		request.Expected.EndpointID == "" || request.Expected.Role.String() == "" ||
		request.Expected.Generation == 0 || request.Now.IsZero() {
		return Certificate{}, ErrInvalid
	}
	root, err := s.repository.ResolveAccountRoot(ctx, request.UserID)
	if err != nil {
		return Certificate{}, err
	}
	key, ok := root.key(request.ExpectedRootFingerprint)
	if !ok || len(key.PublicKey) != ed25519.PublicKeySize || key.Generation == 0 || key.Fingerprint != sha256.Sum256(key.PublicKey) || key.KeyID != request.KeyID {
		return Certificate{}, ErrUnavailable
	}
	certificate, err := validateRegistration(request, key.PublicKey)
	if err != nil {
		return Certificate{}, err
	}
	if request.ExpectedRootFingerprint != key.Fingerprint {
		return Certificate{}, ErrIdentity
	}
	certificate.KeyID = key.KeyID
	certificate.RootFingerprint = key.Fingerprint
	return s.repository.Register(ctx, request.OperationID, request.UserID, certificate)
}

func validateRegistration(request RegisterRequest, rootPublic ed25519.PublicKey) (Certificate, error) {
	if len(request.OperationID) < 16 || len(request.OperationID) > 256 || !identifierExpr.MatchString(request.UserID) || !identifierExpr.MatchString(request.KeyID) || request.Expected.AccountID != request.UserID || request.Expected.EndpointID == "" || request.Expected.Role.String() == "" || request.Expected.Generation == 0 || request.Now.IsZero() {
		return Certificate{}, ErrInvalid
	}
	certificate, err := Verify(request.Certificate, rootPublic, request.Expected, request.Now)
	if err != nil {
		return Certificate{}, err
	}
	if request.ExpectedCertificateFingerprint != certificate.Fingerprint || !request.ExpectedIssuedAt.Equal(certificate.IssuedAt) || !request.ExpectedExpiresAt.Equal(certificate.ExpiresAt) {
		return Certificate{}, ErrIdentity
	}
	return certificate, nil
}

func nilRepository(repository Repository) bool {
	if repository == nil {
		return true
	}
	value := reflect.ValueOf(repository)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func (root AccountRoot) key(fingerprint [sha256.Size]byte) (AccountKey, bool) {
	for _, key := range root.Keys {
		if key.Fingerprint == fingerprint {
			return key, true
		}
	}
	return AccountKey{}, false
}

func keyIDForFingerprint(fingerprint [sha256.Size]byte) string {
	return "aek_" + hex.EncodeToString(fingerprint[:])
}

// KeyID deterministically names the trusted E2EE key represented by publicKey.
// It is intentionally derived from the public material so enrollment requests
// cannot smuggle an unrelated key identifier into a certificate document.
func KeyID(publicKey ed25519.PublicKey) (string, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return "", ErrInvalid
	}
	return keyIDForFingerprint(sha256.Sum256(publicKey)), nil
}

// FingerprintForKeyID validates and decodes the canonical identifier for a
// trusted E2EE public key. The identifier is content-addressed, so callers
// can resolve the key by ID without accepting a second, unauthenticated
// fingerprint field from the wire.
func FingerprintForKeyID(keyID string) ([sha256.Size]byte, error) {
	var fingerprint [sha256.Size]byte
	if len(keyID) != len("aek_")+sha256.Size*2 || !identifierExpr.MatchString(keyID) || !strings.HasPrefix(keyID, "aek_") {
		return fingerprint, ErrInvalid
	}
	decoded, err := hex.DecodeString(keyID[len("aek_"):])
	if err != nil || len(decoded) != len(fingerprint) {
		return fingerprint, ErrInvalid
	}
	copy(fingerprint[:], decoded)
	if keyIDForFingerprint(fingerprint) != keyID {
		return [sha256.Size]byte{}, ErrInvalid
	}
	return fingerprint, nil
}
