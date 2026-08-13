// Package managedssh owns server authority for managed SSH public keys and
// immutable machine host-key observations.
package managedssh

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"
	"regexp"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

var (
	ErrInvalid     = errors.New("managed SSH request is invalid")
	ErrConflict    = errors.New("managed SSH key conflicts with current authority")
	ErrUnavailable = errors.New("managed SSH authority is unavailable")
)

type ClientKey struct {
	Fingerprint           [32]byte
	UserID                string
	CLIClientSessionID    string
	Algorithm             string
	PublicKey             string
	State                 string
	ReconciliationVersion uint64
	CreatedAt             time.Time
	RevokedAt             time.Time
	RevocationReason      string
}

type RegisterClientRequest struct {
	OperationID        string
	UserID             string
	CLIClientSessionID string
	PublicKey          string
	Now                time.Time
}

type RevokeClientRequest struct {
	OperationID string
	ActorUserID string
	Fingerprint [32]byte
	Reason      string
	Now         time.Time
}

type ListClientKeysRequest struct {
	ActorUserID       string
	UserMachineID     string
	MachineGeneration uint64
}

type ClientKeySet struct {
	UserMachineID     string
	MachineGeneration uint64
	Keys              []ClientKey
}

type MachineTarget struct {
	UserMachineID         string
	MachineGeneration     uint64
	OSUser                string
	TargetPort            uint16
	ReconciliationVersion uint64
	CreatedAt             time.Time
	UpdatedAt             time.Time
}

type RegisterTargetRequest struct {
	OperationID       string
	ActorUserID       string
	UserMachineID     string
	MachineGeneration uint64
	OSUser            string
	TargetPort        uint16
	Now               time.Time
}

type UpdateTargetPortRequest struct {
	OperationID                   string
	ActorUserID                   string
	UserMachineID                 string
	MachineGeneration             uint64
	TargetPort                    uint16
	ExpectedReconciliationVersion uint64
	Now                           time.Time
}

type GetTargetRequest struct {
	ActorUserID       string
	UserMachineID     string
	MachineGeneration uint64
}

type HostKey struct {
	Fingerprint [32]byte
	Algorithm   string
	PublicKey   string
}

type HostKeySet struct {
	ID                    string
	UserMachineID         string
	MachineGeneration     uint64
	ObservationGeneration uint64
	Fingerprint           [32]byte
	State                 string
	ReconciliationVersion uint64
	Keys                  []HostKey
	ObservedAt            time.Time
	PromotedAt            time.Time
}

type ObserveHostRequest struct {
	OperationID           string
	SetID                 string
	UserID                string
	UserMachineID         string
	MachineGeneration     uint64
	ObservationGeneration uint64
	PublicKeys            []string
	Now                   time.Time
}

type PromoteHostRequest struct {
	OperationID         string
	ActorUserID         string
	UserMachineID       string
	MachineGeneration   uint64
	SetID               string
	ExpectedFingerprint [32]byte
	Now                 time.Time
}

type GetHostKeySetRequest struct {
	ActorUserID       string
	UserMachineID     string
	MachineGeneration uint64
}

type Repository interface {
	RegisterClient(context.Context, RegisterClientRequest, ClientKey) (ClientKey, error)
	RevokeClient(context.Context, RevokeClientRequest) (ClientKey, error)
	ListClientKeys(context.Context, ListClientKeysRequest) (ClientKeySet, error)
	ObserveHost(context.Context, ObserveHostRequest, HostKeySet) (HostKeySet, error)
	PromoteHost(context.Context, PromoteHostRequest) (HostKeySet, error)
	GetActiveHost(context.Context, GetHostKeySetRequest) (HostKeySet, error)
	GetPendingHost(context.Context, GetHostKeySetRequest) (HostKeySet, error)
	RegisterTarget(context.Context, RegisterTargetRequest) (MachineTarget, error)
	UpdateTargetPort(context.Context, UpdateTargetPortRequest) (MachineTarget, error)
	GetTarget(context.Context, GetTargetRequest) (MachineTarget, error)
}

func (s *Service) RegisterTarget(ctx context.Context, request RegisterTargetRequest) (MachineTarget, error) {
	if s == nil || s.repository == nil || ctx == nil || !validOperationID(request.OperationID) || !bounded(request.ActorUserID) || !bounded(request.UserMachineID) || request.MachineGeneration == 0 || request.MachineGeneration > math.MaxInt64 || !validOSUser(request.OSUser) || request.TargetPort == 0 || request.Now.IsZero() {
		return MachineTarget{}, ErrInvalid
	}
	request.Now = request.Now.UTC()
	return s.repository.RegisterTarget(ctx, request)
}

func (s *Service) UpdateTargetPort(ctx context.Context, request UpdateTargetPortRequest) (MachineTarget, error) {
	if s == nil || s.repository == nil || ctx == nil || !validOperationID(request.OperationID) || !bounded(request.ActorUserID) || !bounded(request.UserMachineID) || request.MachineGeneration == 0 || request.MachineGeneration > math.MaxInt64 || request.TargetPort == 0 || request.ExpectedReconciliationVersion == 0 || request.ExpectedReconciliationVersion > math.MaxInt64 || request.Now.IsZero() {
		return MachineTarget{}, ErrInvalid
	}
	request.Now = request.Now.UTC()
	return s.repository.UpdateTargetPort(ctx, request)
}

func (s *Service) GetTarget(ctx context.Context, request GetTargetRequest) (MachineTarget, error) {
	if s == nil || s.repository == nil || ctx == nil || !bounded(request.ActorUserID) || !bounded(request.UserMachineID) || request.MachineGeneration == 0 || request.MachineGeneration > math.MaxInt64 {
		return MachineTarget{}, ErrInvalid
	}
	return s.repository.GetTarget(ctx, request)
}

type Service struct{ repository Repository }

func NewService(repository Repository) (*Service, error) {
	if repository == nil {
		return nil, ErrInvalid
	}
	return &Service{repository: repository}, nil
}

func (s *Service) RegisterClient(ctx context.Context, request RegisterClientRequest) (ClientKey, error) {
	if s == nil || s.repository == nil || ctx == nil || !validOperationID(request.OperationID) || !bounded(request.UserID) || !bounded(request.CLIClientSessionID) || request.Now.IsZero() {
		return ClientKey{}, ErrInvalid
	}
	key, err := parsePublicKey(request.PublicKey, true)
	if err != nil {
		return ClientKey{}, err
	}
	key.UserID, key.CLIClientSessionID, key.State = request.UserID, request.CLIClientSessionID, "active"
	key.ReconciliationVersion, key.CreatedAt = 1, request.Now.UTC()
	return s.repository.RegisterClient(ctx, request, key)
}

func (s *Service) RevokeClient(ctx context.Context, request RevokeClientRequest) (ClientKey, error) {
	if s == nil || s.repository == nil || ctx == nil || !validOperationID(request.OperationID) || !bounded(request.ActorUserID) || request.Fingerprint == [32]byte{} || !validClientRevocation(request.Reason) || request.Now.IsZero() {
		return ClientKey{}, ErrInvalid
	}
	request.Now = request.Now.UTC()
	return s.repository.RevokeClient(ctx, request)
}

func (s *Service) ListClientKeys(ctx context.Context, request ListClientKeysRequest) (ClientKeySet, error) {
	if s == nil || s.repository == nil || ctx == nil || !bounded(request.ActorUserID) || !bounded(request.UserMachineID) || request.MachineGeneration == 0 || request.MachineGeneration > math.MaxInt64 {
		return ClientKeySet{}, ErrInvalid
	}
	return s.repository.ListClientKeys(ctx, request)
}

func (s *Service) ObserveHost(ctx context.Context, request ObserveHostRequest) (HostKeySet, error) {
	if s == nil || s.repository == nil || ctx == nil || !validOperationID(request.OperationID) || !validHostKeySetID(request.SetID) || !bounded(request.UserID) || !bounded(request.UserMachineID) || request.MachineGeneration == 0 || request.MachineGeneration > math.MaxInt64 || request.ObservationGeneration == 0 || request.ObservationGeneration > math.MaxInt64 || len(request.PublicKeys) == 0 || len(request.PublicKeys) > 8 || request.Now.IsZero() {
		return HostKeySet{}, ErrInvalid
	}
	keys := make([]HostKey, 0, len(request.PublicKeys))
	seen := make(map[[32]byte]bool, len(request.PublicKeys))
	for _, raw := range request.PublicKeys {
		key, err := parsePublicKey(raw, false)
		if err != nil || seen[key.Fingerprint] {
			return HostKeySet{}, ErrInvalid
		}
		seen[key.Fingerprint] = true
		keys = append(keys, HostKey{Fingerprint: key.Fingerprint, Algorithm: key.Algorithm, PublicKey: key.PublicKey})
	}
	slices.SortFunc(keys, func(a, b HostKey) int { return strings.Compare(string(a.Fingerprint[:]), string(b.Fingerprint[:])) })
	set := HostKeySet{ID: request.SetID, UserMachineID: request.UserMachineID, MachineGeneration: request.MachineGeneration, ObservationGeneration: request.ObservationGeneration, Fingerprint: fingerprintSet(keys), ReconciliationVersion: 1, Keys: keys, ObservedAt: request.Now.UTC()}
	return s.repository.ObserveHost(ctx, request, set)
}

func (s *Service) PromoteHost(ctx context.Context, request PromoteHostRequest) (HostKeySet, error) {
	if s == nil || s.repository == nil || ctx == nil || !validOperationID(request.OperationID) || !bounded(request.ActorUserID) || !bounded(request.UserMachineID) || request.MachineGeneration == 0 || request.MachineGeneration > math.MaxInt64 || !validHostKeySetID(request.SetID) || request.ExpectedFingerprint == [32]byte{} || request.Now.IsZero() {
		return HostKeySet{}, ErrInvalid
	}
	request.Now = request.Now.UTC()
	return s.repository.PromoteHost(ctx, request)
}

func (s *Service) GetActiveHost(ctx context.Context, request GetHostKeySetRequest) (HostKeySet, error) {
	if s == nil || s.repository == nil || ctx == nil || !bounded(request.ActorUserID) || !bounded(request.UserMachineID) || request.MachineGeneration == 0 || request.MachineGeneration > math.MaxInt64 {
		return HostKeySet{}, ErrInvalid
	}
	return s.repository.GetActiveHost(ctx, request)
}

func (s *Service) GetPendingHost(ctx context.Context, request GetHostKeySetRequest) (HostKeySet, error) {
	if s == nil || s.repository == nil || ctx == nil || !bounded(request.ActorUserID) || !bounded(request.UserMachineID) || request.MachineGeneration == 0 || request.MachineGeneration > math.MaxInt64 {
		return HostKeySet{}, ErrInvalid
	}
	return s.repository.GetPendingHost(ctx, request)
}

var hostKeySetIDPattern = regexp.MustCompile(`^sshks_[A-Za-z0-9_-]{16,128}$`)

func validHostKeySetID(value string) bool { return hostKeySetIDPattern.MatchString(value) }

func validOperationID(value string) bool {
	if len(value) < 16 || len(value) > 256 {
		return false
	}
	for _, character := range value {
		if character == 0 || character == '\r' || character == '\n' || character == ' ' {
			return false
		}
	}
	return true
}

func parsePublicKey(raw string, client bool) (ClientKey, error) {
	if len(raw) < 32 || len(raw) > 8192 || strings.ContainsAny(raw, "\r\x00") {
		return ClientKey{}, ErrInvalid
	}
	public, comment, options, rest, err := ssh.ParseAuthorizedKey([]byte(raw))
	if err != nil || len(options) != 0 || len(strings.TrimSpace(string(rest))) != 0 || strings.ContainsAny(comment, "\r\n\x00") {
		return ClientKey{}, ErrInvalid
	}
	algorithm := public.Type()
	if client && algorithm != ssh.KeyAlgoED25519 || !client && !validHostAlgorithm(algorithm) {
		return ClientKey{}, ErrInvalid
	}
	canonical := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(public)))
	return ClientKey{Fingerprint: sha256.Sum256(public.Marshal()), Algorithm: algorithm, PublicKey: canonical}, nil
}

// ClientFingerprint validates a managed SSH client key and returns the
// canonical resource fingerprint used by the HTTP contract.
func ClientFingerprint(raw string) ([32]byte, error) {
	key, err := parsePublicKey(raw, true)
	return key.Fingerprint, err
}

func fingerprintSet(keys []HostKey) [32]byte {
	hash := sha256.New()
	_, _ = hash.Write([]byte("paperboat-ssh-host-key-set-v1"))
	for _, key := range keys {
		var length [2]byte
		binary.BigEndian.PutUint16(length[:], uint16(len(key.PublicKey)))
		_, _ = hash.Write(length[:])
		_, _ = hash.Write([]byte(key.PublicKey))
	}
	var result [32]byte
	copy(result[:], hash.Sum(nil))
	return result
}

func validHostAlgorithm(value string) bool {
	switch value {
	case ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521, ssh.KeyAlgoRSA:
		return true
	default:
		return false
	}
}

func validClientRevocation(value string) bool {
	switch value {
	case "client_revoked", "client_logout", "account_revoked", "key_rotated", "key_compromise":
		return true
	default:
		return false
	}
}

func bounded(value string) bool {
	return len(value) > 0 && len(value) <= 128 && !strings.ContainsAny(value, "\r\n\x00")
}

func validOSUser(value string) bool {
	if value == "" || len(value) > 255 || value[0] == '-' || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\r\n\x00@") {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}
