package connectorprotocol

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
)

var (
	ErrDurableReplay       = errors.New("connector proof was already consumed")
	ErrConnectorNotFound   = errors.New("connector is not enrolled or is revoked")
	ErrStaleProcess        = errors.New("connector process generation is stale")
	ErrSessionNotFound     = errors.New("connector session is not active")
	ErrConfigNotFound      = errors.New("tunnel configuration generation is not available")
	ErrConfigHashCorrupt   = errors.New("tunnel configuration content hash is corrupt")
	ErrProofKeyUnavailable = errors.New("enrolled connector proof key is unavailable")
	ErrOperationNotFound   = errors.New("connector operation is not available")
)

// SQLControlStore is the production persistence adapter for connector-v1. It
// deliberately keeps the protocol package independent of sqlc models: all
// lifecycle transitions below run in DB.InTx and lock the exact connector,
// credential generation, configuration generation, and session rows involved.
// No bearer credential or private key is ever read into this process.
type SQLControlStore struct {
	DB               *db.DB
	Clock            Clock
	LeaseDuration    time.Duration
	SessionRetention time.Duration
}

type SQLControlStoreConfig struct {
	Clock            Clock
	LeaseDuration    time.Duration
	SessionRetention time.Duration
}

func NewSQLControlStore(database *db.DB, config SQLControlStoreConfig) (*SQLControlStore, error) {
	if database == nil {
		return nil, ErrInvalidInput
	}
	if config.LeaseDuration == 0 {
		config.LeaseDuration = DefaultLease
	}
	if config.SessionRetention == 0 {
		config.SessionRetention = 24 * time.Hour
	}
	if config.LeaseDuration <= 0 || config.LeaseDuration > MaxLease || config.SessionRetention <= 0 {
		return nil, ErrInvalidInput
	}
	return &SQLControlStore{DB: database, Clock: config.Clock, LeaseDuration: config.LeaseDuration, SessionRetention: config.SessionRetention}, nil
}

func (s *SQLControlStore) now() time.Time {
	if s != nil && s.Clock != nil {
		return s.Clock.Now().UTC()
	}
	return time.Now().UTC()
}

func (s *SQLControlStore) valid() error {
	if s == nil || s.DB == nil || s.LeaseDuration <= 0 || s.LeaseDuration > MaxLease || s.SessionRetention <= 0 {
		return ErrInvalidInput
	}
	return nil
}

type proofMaterial struct {
	AccountID             string
	HostID                string
	HostPublicIdentityKey string
	CredentialThumbprint  string
	CredentialAlgorithm   string
	CredentialPublicKey   []byte
	CredentialValidUntil  time.Time
}

func (s *SQLControlStore) loadProofMaterial(ctx context.Context, tx *db.Tx, accountID, tunnelID, connectorID, hostID string, credentialGeneration uint64, now time.Time, lock bool) (proofMaterial, error) {
	if credentialGeneration == 0 {
		return proofMaterial{}, ErrAuthenticationFailed
	}
	query := `
SELECT t.account_id, c.host_id, m.public_identity_key,
       cg.credential_thumbprint, cg.verifier_algorithm,
       cg.verifier_public_key, cg.valid_until
FROM tunnel_connectors AS c
JOIN tunnels AS t ON t.id = c.tunnel_id
JOIN user_machines AS m ON m.id = c.host_id AND m.user_id = t.account_id
JOIN tunnel_connector_credential_generations AS cg
  ON cg.connector_id = c.id AND cg.tunnel_id = c.tunnel_id
WHERE t.account_id = $1
  AND t.id = $2
  AND t.deleted_at IS NULL
  AND c.id = $3
  AND c.host_id = $4
  AND c.revoked_at IS NULL
  AND c.desired_state <> 'revoked'
  AND m.revoked_at IS NULL
  AND m.deleted_at IS NULL
  AND m.public_identity_key IS NOT NULL
  AND cg.generation = $5
  AND cg.state IN ('active', 'overlap')
  AND cg.valid_until > $6`
	if lock {
		query += `
FOR UPDATE OF c, cg`
	}
	var material proofMaterial
	if err := tx.QueryRow(ctx, query, accountID, tunnelID, connectorID, hostID, int64(credentialGeneration), now).Scan(
		&material.AccountID,
		&material.HostID,
		&material.HostPublicIdentityKey,
		&material.CredentialThumbprint,
		&material.CredentialAlgorithm,
		&material.CredentialPublicKey,
		&material.CredentialValidUntil,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return proofMaterial{}, ErrConnectorNotFound
		}
		return proofMaterial{}, err
	}
	if material.AccountID != accountID || material.HostID != hostID || !material.CredentialValidUntil.After(now) {
		return proofMaterial{}, ErrConnectorNotFound
	}
	return material, nil
}

func decodeStoredPublicKey(encoded string) (ed25519.PublicKey, error) {
	value := strings.TrimSpace(encoded)
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, ErrProofKeyUnavailable
	}
	return ed25519.PublicKey(decoded), nil
}

func (m proofMaterial) proofKey(identityKeyID, identityThumbprint string) (ed25519.PublicKey, error) {
	if m.CredentialAlgorithm != "ed25519" || len(m.CredentialPublicKey) != ed25519.PublicKeySize {
		return nil, ErrProofKeyUnavailable
	}
	// Host identity is the normal control proof authority. The credential
	// verifier key is also accepted when its RFC7638 identity is presented;
	// this is what permits a credential-key rotation to prove possession while
	// retaining the same durable connector/host authorization.
	hostKey, hostErr := decodeStoredPublicKey(m.HostPublicIdentityKey)
	if hostErr == nil {
		hostThumbprint, thumbErr := IdentityThumbprint(hostKey)
		if thumbErr == nil && identityKeyID == "ed25519:"+hostThumbprint && identityThumbprint == hostThumbprint {
			return hostKey, nil
		}
	}
	credentialKey := ed25519.PublicKey(append([]byte(nil), m.CredentialPublicKey...))
	if credentialThumbprint, err := IdentityThumbprint(credentialKey); err == nil && identityKeyID == "ed25519:"+credentialThumbprint && identityThumbprint == credentialThumbprint && identityThumbprint == m.CredentialThumbprint {
		return credentialKey, nil
	}
	return nil, ErrProofKeyUnavailable
}

func verifyTranscript(expected, supplied, signed []byte, key ed25519.PublicKey) error {
	if !bytes.Equal(expected, supplied) || len(key) != ed25519.PublicKeySize || len(signed) != ed25519.SignatureSize || !ed25519.Verify(key, expected, signed) {
		return ErrAuthenticationFailed
	}
	return nil
}

func (s *SQLControlStore) VerifyAuthProof(ctx context.Context, request AuthRequest, payload, signature []byte) error {
	if ctx == nil || s.valid() != nil {
		return ErrAuthenticationFailed
	}
	if err := request.Validate(s.now()); err != nil {
		return err
	}
	expected, err := AuthProofPayload(request)
	if err != nil {
		return err
	}
	now := s.now()
	return s.DB.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		material, err := s.loadProofMaterial(ctx, tx, request.AccountID, request.TunnelID, request.ConnectorID, request.HostID, request.CredentialGeneration, now, false)
		if err != nil {
			return err
		}
		key, err := material.proofKey(request.IdentityKeyID, request.IdentityKeyThumbprint)
		if err != nil {
			return err
		}
		return verifyTranscript(expected, payload, signature, key)
	})
}

func (s *SQLControlStore) VerifyRenewalProof(ctx context.Context, request RenewalRequest, payload, signature []byte) error {
	if ctx == nil || s.valid() != nil {
		return ErrAuthenticationFailed
	}
	if err := request.ValidateAt(s.now()); err != nil {
		return err
	}
	expected, err := RenewalProofPayload(request)
	if err != nil {
		return err
	}
	now := s.now()
	return s.DB.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		material, err := s.loadProofMaterial(ctx, tx, request.AccountID, request.TunnelID, request.ConnectorID, request.HostID, request.CredentialGeneration, now, false)
		if err != nil {
			return err
		}
		key, err := material.proofKey(request.IdentityKeyID, request.IdentityKeyThumbprint)
		if err != nil {
			return err
		}
		return verifyTranscript(expected, payload, signature, key)
	})
}

func proofDigest(payload []byte) [sha256.Size]byte { return sha256.Sum256(payload) }

// reserveControlReplay consumes a unique dedicated replay row. The table is
// intentionally separate from operations: authentication proofs are bounded
// security metadata, not user-visible mutation operations.
func reserveControlReplay(ctx context.Context, tx *db.Tx, accountID, tunnelID, connectorID string, credentialGeneration uint64, proofKind, nonce string, payload []byte, expiresAt, now time.Time) error {
	if accountID == "" || tunnelID == "" || connectorID == "" || credentialGeneration == 0 || credentialGeneration > uint64(^uint64(0)>>1) || len(nonce) < 16 || len(nonce) > MaxNonceBytes || strings.TrimSpace(nonce) != nonce || strings.ContainsAny(nonce, "\r\n") || expiresAt.IsZero() || !expiresAt.After(now) || expiresAt.Sub(now) > MaxLease {
		return ErrInvalidInput
	}
	digest := proofDigest(payload)
	var insertedDigest []byte
	// Keep the replay table bounded with a small indexed cleanup batch. A
	// dedicated table is required because operations is the mutation ledger and
	// must not be polluted by authentication proofs.
	if _, err := tx.Exec(ctx, `
WITH expired AS (
  SELECT account_id, tunnel_id, connector_id, proof_digest
  FROM connector_proof_replays
  WHERE expires_at <= $1
  ORDER BY expires_at, account_id, tunnel_id, connector_id, proof_digest
  LIMIT 256
)
DELETE FROM connector_proof_replays AS r
USING expired AS e
WHERE r.account_id = e.account_id
  AND r.tunnel_id = e.tunnel_id
  AND r.connector_id = e.connector_id
  AND r.proof_digest = e.proof_digest`, now); err != nil {
		return err
	}
	switch proofKind {
	case "auth", "renew", "rotation":
	default:
		return ErrInvalidInput
	}
	err := tx.QueryRow(ctx, `
INSERT INTO connector_proof_replays
  (account_id, tunnel_id, connector_id, credential_generation, proof_kind,
   nonce, proof_digest, expires_at, created_at)
VALUES
	  ($1, $2, $3, $4, $5, $6, $7, $8, $9)
ON CONFLICT DO NOTHING
	RETURNING proof_digest`, accountID, tunnelID, connectorID, int64(credentialGeneration), proofKind, nonce, digest[:], expiresAt, now).Scan(&insertedDigest)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrDurableReplay
	}
	return err
}

func (s *SQLControlStore) AuthenticateConnector(ctx context.Context, request AuthRequest) (AuthResult, error) {
	if ctx == nil || s.valid() != nil {
		return AuthResult{}, ErrInvalidInput
	}
	now := s.now()
	if err := request.Validate(now); err != nil {
		return AuthResult{}, err
	}
	payload, err := AuthProofPayload(request)
	if err != nil {
		return AuthResult{}, err
	}
	signature, err := DecodeProof(request.SignedProof)
	if err != nil {
		return AuthResult{}, err
	}
	var result AuthResult
	err = s.DB.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		material, err := s.loadProofMaterial(ctx, tx, request.AccountID, request.TunnelID, request.ConnectorID, request.HostID, request.CredentialGeneration, now, true)
		if err != nil {
			return err
		}
		key, err := material.proofKey(request.IdentityKeyID, request.IdentityKeyThumbprint)
		if err != nil {
			return err
		}
		if err := verifyTranscript(payload, payload, signature, key); err != nil {
			return err
		}
		if err := reserveControlReplay(ctx, tx, request.AccountID, request.TunnelID, request.ConnectorID, request.CredentialGeneration, "auth", request.Nonce, payload, request.ExpiresAt, now); err != nil {
			return err
		}
		leaseExpiry := now.Add(s.LeaseDuration)
		if material.CredentialValidUntil.Before(leaseExpiry) {
			leaseExpiry = material.CredentialValidUntil
		}
		if !leaseExpiry.After(now) {
			return ErrCredentialExpired
		}
		result = AuthResult{
			AccountID: request.AccountID, TunnelID: request.TunnelID, ConnectorID: request.ConnectorID,
			HostID: request.HostID, IdentityKeyID: request.IdentityKeyID,
			IdentityKeyThumbprint: request.IdentityKeyThumbprint, ProcessGeneration: request.ProcessGeneration,
			CredentialGeneration: request.CredentialGeneration, CredentialExpiresAt: material.CredentialValidUntil,
			LeaseExpiresAt: leaseExpiry,
		}
		return nil
	})
	return result, err
}

func (s *SQLControlStore) RenewConnector(ctx context.Context, request RenewalRequest) (AuthResult, error) {
	if ctx == nil || s.valid() != nil {
		return AuthResult{}, ErrInvalidInput
	}
	now := s.now()
	if err := request.ValidateAt(now); err != nil {
		return AuthResult{}, err
	}
	payload, err := RenewalProofPayload(request)
	if err != nil {
		return AuthResult{}, err
	}
	signature, err := DecodeProof(request.SignedProof)
	if err != nil {
		return AuthResult{}, err
	}
	var result AuthResult
	err = s.DB.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		material, err := s.loadProofMaterial(ctx, tx, request.AccountID, request.TunnelID, request.ConnectorID, request.HostID, request.CredentialGeneration, now, true)
		if err != nil {
			return err
		}
		key, err := material.proofKey(request.IdentityKeyID, request.IdentityKeyThumbprint)
		if err != nil {
			return err
		}
		if err := verifyTranscript(payload, payload, signature, key); err != nil {
			return err
		}
		var state string
		if err := tx.QueryRow(ctx, `
SELECT s.state
FROM tunnel_connector_sessions AS s
JOIN tunnel_connectors AS c ON c.id = s.connector_id
JOIN tunnels AS t ON t.id = c.tunnel_id
WHERE s.id = $1 AND s.connector_id = $2 AND s.process_generation = $3
  AND c.id = $2 AND c.tunnel_id = $4 AND c.host_id = $5
  AND t.account_id = $6 AND t.deleted_at IS NULL
  AND s.credential_generation = $7
  AND s.lease_deadline > $8
  AND s.state IN ('authenticating', 'ready', 'draining')
FOR UPDATE OF s, c`, request.SessionID, request.ConnectorID, int64(request.ProcessGeneration), request.TunnelID, request.HostID, request.AccountID, int64(request.CredentialGeneration), now).Scan(&state); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrSessionNotFound
			}
			return err
		}
		if state == "" {
			return ErrSessionNotFound
		}
		if err := reserveControlReplay(ctx, tx, request.AccountID, request.TunnelID, request.ConnectorID, request.CredentialGeneration, "renew", request.Nonce, payload, now.Add(MaxClockSkew), now); err != nil {
			return err
		}
		leaseExpiry := now.Add(s.LeaseDuration)
		if material.CredentialValidUntil.Before(leaseExpiry) {
			leaseExpiry = material.CredentialValidUntil
		}
		if !leaseExpiry.After(now) {
			return ErrCredentialExpired
		}
		if _, err := tx.Exec(ctx, `
UPDATE tunnel_connector_sessions
SET lease_deadline = $1, last_heartbeat_at = $2
WHERE id = $3 AND connector_id = $4 AND process_generation = $5`, leaseExpiry, now, request.SessionID, request.ConnectorID, int64(request.ProcessGeneration)); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
UPDATE tunnel_connectors
SET last_session_id = $1, last_heartbeat_at = $2, updated_at = $2
WHERE id = $3 AND tunnel_id = $4 AND host_id = $5 AND revoked_at IS NULL`, request.SessionID, now, request.ConnectorID, request.TunnelID, request.HostID); err != nil {
			return err
		}
		result = AuthResult{
			AccountID: request.AccountID, TunnelID: request.TunnelID, ConnectorID: request.ConnectorID,
			SessionID: request.SessionID, HostID: request.HostID, IdentityKeyID: request.IdentityKeyID,
			IdentityKeyThumbprint: request.IdentityKeyThumbprint, ProcessGeneration: request.ProcessGeneration,
			CredentialGeneration: request.CredentialGeneration, CredentialExpiresAt: material.CredentialValidUntil,
			LeaseExpiresAt: leaseExpiry,
		}
		return nil
	})
	return result, err
}

func configHashMatches(stored []byte, snapshot Snapshot) bool {
	if len(stored) != sha256.Size {
		return false
	}
	digest, err := hex.DecodeString(strings.TrimPrefix(snapshot.ContentHash, "sha256:"))
	return err == nil && bytes.Equal(stored, digest)
}

func (s *SQLControlStore) Snapshot(ctx context.Context, tunnelID string) (Snapshot, error) {
	if ctx == nil || s.valid() != nil || ValidateIdentifier(tunnelID) != nil {
		return Snapshot{}, ErrInvalidInput
	}
	var result Snapshot
	err := s.DB.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		var generation int64
		var storedHash, payload []byte
		if err := tx.QueryRow(ctx, `
SELECT g.generation, g.content_hash, g.snapshot
FROM tunnel_config_generations AS g
JOIN tunnels AS t ON t.id = g.tunnel_id
WHERE g.tunnel_id = $1 AND t.deleted_at IS NULL
ORDER BY g.generation DESC
LIMIT 1`, tunnelID).Scan(&generation, &storedHash, &payload); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrConfigNotFound
			}
			return err
		}
		if generation <= 0 || uint64(generation) > ^uint64(0)>>1 {
			return ErrConfigNotFound
		}
		candidate, err := NewSnapshot(tunnelID, uint64(generation), payload)
		if err != nil {
			return err
		}
		if !configHashMatches(storedHash, candidate) {
			return ErrConfigHashCorrupt
		}
		if err := validateConfigSnapshotPayload(candidate.Payload, tunnelID, uint64(generation)); err != nil {
			return err
		}
		result = candidate
		return nil
	})
	return result, err
}

func (s *SQLControlStore) CreateConnectorSession(ctx context.Context, ref SessionRef, lease Lease, credentialGeneration uint64) error {
	return s.createConnectorSession(ctx, ref, lease, credentialGeneration, ProtocolVersion, nil)
}

// CreateConnectorSessionV1 is the metadata-rich variant used by
// PersistentServer. The legacy-shaped method above remains a narrow adapter
// for callers that only have a lease; SQL persistence always stores the
// negotiated version and capabilities when available.
func (s *SQLControlStore) CreateConnectorSessionV1(ctx context.Context, ref SessionRef, welcome Welcome, credentialGeneration uint64) error {
	if err := welcome.Validate(time.Time{}); err != nil {
		return err
	}
	return s.createConnectorSession(ctx, ref, welcome.Lease, credentialGeneration, welcome.Version, append([]string(nil), welcome.Capabilities...))
}

func (s *SQLControlStore) createConnectorSession(ctx context.Context, ref SessionRef, lease Lease, credentialGeneration uint64, protocolVersion string, capabilities []string) error {
	if ctx == nil || s.valid() != nil || ref.Validate() != nil || lease.SessionID != ref.SessionID || credentialGeneration == 0 || protocolVersion != ProtocolVersion {
		return ErrInvalidInput
	}
	now := s.now()
	if lease.Validate(now) != nil {
		return ErrInvalidInput
	}
	retainedUntil := now.Add(s.SessionRetention)
	if !retainedUntil.After(lease.ExpiresAt) {
		retainedUntil = lease.ExpiresAt.Add(time.Second)
	}
	return s.DB.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		var hostID string
		if err := tx.QueryRow(ctx, `
SELECT host_id
FROM tunnel_connectors
WHERE id = $1 AND tunnel_id = $2 AND revoked_at IS NULL
  AND desired_state <> 'revoked'
FOR UPDATE`, ref.ConnectorID, ref.TunnelID).Scan(&hostID); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrConnectorNotFound
			}
			return err
		}
		var credentialState string
		var credentialValidUntil time.Time
		if err := tx.QueryRow(ctx, `
SELECT state, valid_until
FROM tunnel_connector_credential_generations
WHERE connector_id = $1 AND tunnel_id = $2 AND generation = $3
  AND state IN ('active','overlap') AND valid_until >= $4
FOR UPDATE`, ref.ConnectorID, ref.TunnelID, int64(credentialGeneration), lease.ExpiresAt).Scan(&credentialState, &credentialValidUntil); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrCredentialExpired
			}
			return err
		}
		if credentialState == "" || credentialValidUntil.Before(lease.ExpiresAt) {
			// The lease is bounded by the exact credential generation. Keeping
			// this check after the row lock closes the auth/session TOCTOU gap.
			return ErrCredentialExpired
		}
		var highest int64
		if err := tx.QueryRow(ctx, `SELECT COALESCE(MAX(process_generation), 0) FROM tunnel_connector_sessions WHERE connector_id = $1`, ref.ConnectorID).Scan(&highest); err != nil {
			return err
		}
		if highest >= int64(ref.ProcessGeneration) {
			return ErrStaleProcess
		}
		if _, err := tx.Exec(ctx, `
UPDATE tunnel_connector_sessions
SET state = 'disconnected', disconnected_at = $1,
    disconnect_reason_code = 'session_replaced'
WHERE connector_id = $2 AND process_generation < $3
  AND state IN ('authenticating', 'ready', 'draining')`, now, ref.ConnectorID, int64(ref.ProcessGeneration)); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
INSERT INTO tunnel_connector_sessions
  (id, connector_id, process_generation, protocol_version, capabilities,
   credential_generation, state, lease_deadline, last_heartbeat_at, applied_config_generation,
   retained_until, created_at)
VALUES ($1, $2, $3, $4, $5, $6, 'authenticating', $7, $8, 0, $9, $8)`, ref.SessionID, ref.ConnectorID, int64(ref.ProcessGeneration), protocolVersion, capabilities, int64(credentialGeneration), lease.ExpiresAt, now, retainedUntil); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrStaleProcess
			}
			return err
		}
		_, err := tx.Exec(ctx, `
UPDATE tunnel_connectors
SET last_session_id = $1, last_heartbeat_at = $2, ready_at = NULL,
    disconnect_reason_code = NULL, updated_at = $2
WHERE id = $3 AND tunnel_id = $4 AND host_id = $5`, ref.SessionID, now, ref.ConnectorID, ref.TunnelID, hostID)
		return err
	})
}

func (s *SQLControlStore) lockSession(ctx context.Context, tx *db.Tx, ref SessionRef, now time.Time) (string, error) {
	var state, accountID, tunnelID string
	err := tx.QueryRow(ctx, `
SELECT s.state, t.account_id, c.tunnel_id
FROM tunnel_connector_sessions AS s
JOIN tunnel_connectors AS c ON c.id = s.connector_id
JOIN tunnels AS t ON t.id = c.tunnel_id
WHERE s.id = $1 AND s.connector_id = $2 AND s.process_generation = $3
  AND c.tunnel_id = $4 AND t.deleted_at IS NULL
  AND s.state IN ('authenticating', 'ready', 'draining')
  AND s.lease_deadline > $5
FOR UPDATE OF s, c`, ref.SessionID, ref.ConnectorID, int64(ref.ProcessGeneration), ref.TunnelID, now).Scan(&state, &accountID, &tunnelID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrSessionNotFound
	}
	if err != nil {
		return "", err
	}
	if tunnelID != ref.TunnelID || state == "" {
		return "", ErrSessionNotFound
	}
	return accountID, nil
}

func (s *SQLControlStore) generationHash(ctx context.Context, tx *db.Tx, tunnelID string, generation uint64) ([]byte, error) {
	if generation == 0 || generation > uint64(^uint64(0)>>1) {
		return nil, ErrConfigNotFound
	}
	var stored []byte
	if err := tx.QueryRow(ctx, `SELECT content_hash FROM tunnel_config_generations WHERE tunnel_id = $1 AND generation = $2`, tunnelID, int64(generation)).Scan(&stored); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrConfigNotFound
		}
		return nil, err
	}
	if len(stored) != sha256.Size {
		return nil, ErrConfigHashCorrupt
	}
	return stored, nil
}

func (s *SQLControlStore) updateConnectorOperation(ctx context.Context, tx *db.Tx, ref SessionRef, now time.Time, ready bool) error {
	if ready {
		_, err := tx.Exec(ctx, `
WITH candidate AS (
  SELECT o.id
  FROM operations AS o
  JOIN tunnel_connector_sessions AS s
    ON s.id = $2 AND s.connector_id = $1 AND s.process_generation = $3
  JOIN tunnel_connector_credential_generations AS cg
    ON cg.connector_id = s.connector_id
   AND cg.generation = s.credential_generation
   AND cg.source_operation_id = o.id
  WHERE o.resource_kind = 'connector' AND o.resource_id = $1
    AND o.operation_type = 'connector.enrollment.exchange'
    AND o.state IN ('pending', 'running', 'uncertain')
  ORDER BY o.created_at DESC, o.id DESC
  LIMIT 1
)
UPDATE operations AS o
SET phase = 'ready', state = 'succeeded', progress = 100,
    outcome = CASE WHEN o.outcome = 'unchanged' THEN 'changed' ELSE o.outcome END,
    completed_at = $4, updated_at = $4
FROM candidate AS c
WHERE o.id = c.id`, ref.ConnectorID, ref.SessionID, int64(ref.ProcessGeneration), now)
		return err
	}
	_, err := tx.Exec(ctx, `
WITH candidate AS (
  SELECT o.id
  FROM operations AS o
  JOIN tunnel_connector_sessions AS s
    ON s.id = $2 AND s.connector_id = $1 AND s.process_generation = $3
  JOIN tunnel_connector_credential_generations AS cg
    ON cg.connector_id = s.connector_id
   AND cg.generation = s.credential_generation
   AND cg.source_operation_id = o.id
  WHERE o.resource_kind = 'connector' AND o.resource_id = $1
    AND o.operation_type = 'connector.enrollment.exchange'
    AND o.state IN ('pending', 'running', 'uncertain')
  ORDER BY o.created_at DESC, o.id DESC
  LIMIT 1
)
UPDATE operations AS o
SET phase = 'connecting', state = 'running', progress = GREATEST(o.progress, 60),
    updated_at = $4
FROM candidate AS c
WHERE o.id = c.id`, ref.ConnectorID, ref.SessionID, int64(ref.ProcessGeneration), now)
	return err
}

func (s *SQLControlStore) updateConnectorOperationFailure(ctx context.Context, tx *db.Tx, ref SessionRef, now time.Time, code Code) error {
	_, err := tx.Exec(ctx, `
WITH candidate AS (
  SELECT o.id
  FROM operations AS o
  JOIN tunnel_connector_sessions AS s
    ON s.id = $2 AND s.connector_id = $1 AND s.process_generation = $3
  JOIN tunnel_connector_credential_generations AS cg
    ON cg.connector_id = s.connector_id
   AND cg.generation = s.credential_generation
   AND cg.source_operation_id = o.id
  WHERE o.resource_kind = 'connector' AND o.resource_id = $1
    AND o.operation_type = 'connector.enrollment.exchange'
    AND o.state IN ('pending', 'running', 'uncertain')
  ORDER BY o.created_at DESC, o.id DESC
  LIMIT 1
)
UPDATE operations AS o
SET phase = 'failed', state = 'failed', progress = 100,
    error_code = $4, outcome = 'uncertain', completed_at = $5, updated_at = $5
FROM candidate AS c
WHERE o.id = c.id`, ref.ConnectorID, ref.SessionID, int64(ref.ProcessGeneration), string(code), now)
	return err
}

func (s *SQLControlStore) updateConnectorOperationRecovery(ctx context.Context, tx *db.Tx, ref SessionRef, now time.Time, code Code) error {
	_, err := tx.Exec(ctx, `
WITH candidate AS (
  SELECT o.id
  FROM operations AS o
  JOIN tunnel_connector_sessions AS s
    ON s.id = $2 AND s.connector_id = $1 AND s.process_generation = $3
  JOIN tunnel_connector_credential_generations AS cg
    ON cg.connector_id = s.connector_id
   AND cg.generation = s.credential_generation
   AND cg.source_operation_id = o.id
  WHERE o.resource_kind = 'connector' AND o.resource_id = $1
    AND o.operation_type = 'connector.enrollment.exchange'
    AND o.state IN ('pending', 'running', 'uncertain')
  ORDER BY o.created_at DESC, o.id DESC
  LIMIT 1
)
UPDATE operations AS o
SET phase = 'connecting', state = 'running', progress = GREATEST(o.progress, 60),
    error_code = $4, updated_at = $5
FROM candidate AS c
WHERE o.id = c.id`, ref.ConnectorID, ref.SessionID, int64(ref.ProcessGeneration), string(code), now)
	return err
}

func (s *SQLControlStore) RecordApplied(ctx context.Context, ref SessionRef, ack Ack) error {
	if ctx == nil || s.valid() != nil || ref.Validate() != nil || ack.Validate() != nil || !matchesAckRef(ref, ack) {
		return ErrInvalidInput
	}
	now := s.now()
	return s.DB.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		accountID, err := s.lockSession(ctx, tx, ref, now)
		if err != nil {
			return err
		}
		if ack.AccountID != accountID {
			return ErrIdentityMismatch
		}
		switch ack.Status {
		case AckApplied, AckDuplicate:
			storedHash, err := s.generationHash(ctx, tx, ref.TunnelID, ack.Generation)
			if err != nil {
				return err
			}
			if !configHashMatches(storedHash, Snapshot{ContentHash: ack.ContentHash}) {
				return ErrConfigHashCorrupt
			}
			if _, err := tx.Exec(ctx, `
UPDATE tunnel_connector_sessions
SET applied_config_generation = GREATEST(applied_config_generation, $1)
WHERE id = $2 AND connector_id = $3 AND process_generation = $4`, int64(ack.Generation), ref.SessionID, ref.ConnectorID, int64(ref.ProcessGeneration)); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `
UPDATE tunnel_connectors
SET last_applied_config_generation = GREATEST(last_applied_config_generation, $1), updated_at = $2
WHERE id = $3 AND tunnel_id = $4`, int64(ack.Generation), now, ref.ConnectorID, ref.TunnelID); err != nil {
				return err
			}
			if err := s.updateConnectorOperation(ctx, tx, ref, now, false); err != nil {
				return err
			}
		case AckRejected:
			if err := s.updateConnectorOperationFailure(ctx, tx, ref, now, CodeSnapshotRejected); err != nil {
				return err
			}
		case AckSnapshotRequired:
			if err := s.updateConnectorOperationRecovery(ctx, tx, ref, now, CodeSnapshotRequired); err != nil {
				return err
			}
		default:
			return ErrInvalidInput
		}
		return nil
	})
}

func matchesAckRef(ref SessionRef, ack Ack) bool {
	return ack.TunnelID == ref.TunnelID && ack.ConnectorID == ref.ConnectorID && ack.SessionID == ref.SessionID && ack.ProcessGeneration == ref.ProcessGeneration
}

func (s *SQLControlStore) RecordReady(ctx context.Context, ref SessionRef, readiness Readiness) error {
	if ctx == nil || s.valid() != nil || ref.Validate() != nil || readiness.Validate() != nil || readiness.TunnelID != ref.TunnelID || readiness.ConnectorID != ref.ConnectorID || readiness.SessionID != ref.SessionID || readiness.ProcessGeneration != ref.ProcessGeneration || !readiness.EdgeReady || !readiness.RouteReady || !readiness.OriginReady {
		return ErrInvalidInput
	}
	now := s.now()
	return s.DB.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		accountID, err := s.lockSession(ctx, tx, ref, now)
		if err != nil {
			return err
		}
		if readiness.AccountID != accountID {
			return ErrIdentityMismatch
		}
		storedHash, err := s.generationHash(ctx, tx, ref.TunnelID, readiness.Generation)
		if err != nil {
			return err
		}
		if !configHashMatches(storedHash, Snapshot{ContentHash: readiness.ContentHash}) {
			return ErrConfigHashCorrupt
		}
		if _, err := tx.Exec(ctx, `
UPDATE tunnel_config_generations
SET activation_state = 'superseded', activated_at = NULL
WHERE tunnel_id = $1 AND activation_state = 'active' AND generation <> $2`, ref.TunnelID, int64(readiness.Generation)); err != nil {
			return err
		}
		result, err := tx.Exec(ctx, `
UPDATE tunnel_config_generations
SET activation_state = 'active', activated_at = $1
		WHERE tunnel_id = $2 AND generation = $3 AND activation_state IN ('pending', 'active')`, now, ref.TunnelID, int64(readiness.Generation))
		if err != nil {
			return err
		}
		if result.RowsAffected() != 1 {
			return ErrConfigNotFound
		}
		if _, err := tx.Exec(ctx, `
UPDATE tunnel_connector_sessions
SET state = 'ready', ready_at = $1, applied_config_generation = $2
WHERE id = $3 AND connector_id = $4 AND process_generation = $5`, now, int64(readiness.Generation), ref.SessionID, ref.ConnectorID, int64(ref.ProcessGeneration)); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
UPDATE tunnel_connectors
SET ready_at = $1, last_applied_config_generation = GREATEST(last_applied_config_generation, $2),
    drain_state = CASE WHEN drain_state = 'draining' THEN drain_state ELSE 'accepting' END,
    updated_at = $1
WHERE id = $3 AND tunnel_id = $4`, now, int64(readiness.Generation), ref.ConnectorID, ref.TunnelID); err != nil {
			return err
		}
		if err := s.updateConnectorOperation(ctx, tx, ref, now, true); err != nil {
			return err
		}
		return nil
	})
}

func (s *SQLControlStore) RecordHeartbeat(ctx context.Context, ref SessionRef, heartbeat Heartbeat, ack HeartbeatAck) error {
	if ctx == nil || s.valid() != nil || ref.Validate() != nil || heartbeat.Validate() != nil || ack.Validate(time.Time{}) != nil || heartbeat.TunnelID != ref.TunnelID || heartbeat.ConnectorID != ref.ConnectorID || heartbeat.SessionID != ref.SessionID || heartbeat.ProcessGeneration != ref.ProcessGeneration || ack.TunnelID != ref.TunnelID || ack.ConnectorID != ref.ConnectorID || ack.SessionID != ref.SessionID || ack.ProcessGeneration != ref.ProcessGeneration || ack.AccountID != heartbeat.AccountID {
		return ErrInvalidInput
	}
	now := s.now()
	if heartbeat.SentAt.Before(now.Add(-MaxClockSkew)) || heartbeat.SentAt.After(now.Add(MaxClockSkew)) {
		return ErrInvalidInput
	}
	if ack.ServerTime.Before(now.Add(-MaxClockSkew)) || ack.ServerTime.After(now.Add(MaxClockSkew)) || !ack.LeaseExpiresAt.After(now) || ack.LeaseExpiresAt.After(now.Add(s.LeaseDuration)) {
		return ErrInvalidInput
	}
	return s.DB.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		accountID, err := s.lockSession(ctx, tx, ref, now)
		if err != nil {
			return err
		}
		if heartbeat.AccountID != accountID {
			return ErrIdentityMismatch
		}
		var lastSentAt sql.NullTime
		if err := tx.QueryRow(ctx, `
SELECT last_heartbeat_sent_at
FROM tunnel_connector_sessions
WHERE id = $1 AND connector_id = $2 AND process_generation = $3
FOR UPDATE`, ref.SessionID, ref.ConnectorID, int64(ref.ProcessGeneration)).Scan(&lastSentAt); err != nil {
			return err
		}
		if lastSentAt.Valid && !heartbeat.SentAt.After(lastSentAt.Time) {
			return ErrDurableReplay
		}
		var credentialExpiry time.Time
		if err := tx.QueryRow(ctx, `
SELECT cg.valid_until
FROM tunnel_connector_sessions AS session
JOIN tunnel_connector_credential_generations AS cg
  ON cg.connector_id = session.connector_id
 AND cg.tunnel_id = $2
 AND cg.generation = session.credential_generation
WHERE session.id = $1 AND session.connector_id = $3
  AND session.process_generation = $4
  AND cg.state IN ('active', 'overlap')
  AND cg.valid_until > $5`, ref.SessionID, ref.TunnelID, ref.ConnectorID, int64(ref.ProcessGeneration), now).Scan(&credentialExpiry); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrCredentialExpired
			}
			return err
		}
		if ack.LeaseExpiresAt.After(credentialExpiry) {
			return ErrCredentialExpired
		}
		storedHash, err := s.generationHash(ctx, tx, ref.TunnelID, heartbeat.LastAppliedGeneration)
		if err != nil {
			return err
		}
		if !configHashMatches(storedHash, Snapshot{ContentHash: heartbeat.LastAppliedHash}) {
			return ErrSnapshotRequired
		}
		if _, err := tx.Exec(ctx, `
UPDATE tunnel_connector_sessions
SET lease_deadline = $1, last_heartbeat_at = GREATEST(last_heartbeat_at, $2),
    last_heartbeat_sent_at = $3
WHERE id = $4 AND connector_id = $5 AND process_generation = $6`, ack.LeaseExpiresAt, now, heartbeat.SentAt, ref.SessionID, ref.ConnectorID, int64(ref.ProcessGeneration)); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `
UPDATE tunnel_connectors
SET last_session_id = $1, last_heartbeat_at = GREATEST(last_heartbeat_at, $2), updated_at = GREATEST(updated_at, $2)
WHERE id = $3 AND tunnel_id = $4`, ref.SessionID, now, ref.ConnectorID, ref.TunnelID)
		return err
	})
}

func (s *SQLControlStore) RecordRenewal(ctx context.Context, ref SessionRef, result AuthResult) error {
	if ctx == nil || s.valid() != nil || ref.Validate() != nil {
		return ErrInvalidInput
	}
	now := s.now()
	if result.Validate(now) != nil || result.AccountID == "" || result.TunnelID != ref.TunnelID || result.ConnectorID != ref.ConnectorID || result.SessionID != ref.SessionID || result.ProcessGeneration != ref.ProcessGeneration || result.LeaseExpiresAt.After(now.Add(s.LeaseDuration)) {
		return ErrInvalidInput
	}
	return s.DB.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		accountID, err := s.lockSession(ctx, tx, ref, now)
		if err != nil {
			return err
		}
		if result.AccountID != accountID {
			return ErrIdentityMismatch
		}
		if _, err := tx.Exec(ctx, `
UPDATE tunnel_connector_sessions
SET lease_deadline = $1, last_heartbeat_at = $2
WHERE id = $3 AND connector_id = $4 AND process_generation = $5`, result.LeaseExpiresAt, now, ref.SessionID, ref.ConnectorID, int64(ref.ProcessGeneration)); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `
UPDATE tunnel_connectors
SET last_session_id = $1, last_heartbeat_at = $2, updated_at = $2
WHERE id = $3 AND tunnel_id = $4`, ref.SessionID, now, ref.ConnectorID, ref.TunnelID)
		return err
	})
}

func (s *SQLControlStore) RecordDisconnected(ctx context.Context, ref SessionRef, disconnect Disconnect) error {
	if ctx == nil || s.valid() != nil || ref.Validate() != nil || disconnect.Validate() != nil || disconnect.TunnelID != ref.TunnelID || disconnect.ConnectorID != ref.ConnectorID || disconnect.SessionID != ref.SessionID || disconnect.ProcessGeneration != ref.ProcessGeneration {
		return ErrInvalidInput
	}
	now := s.now()
	return s.DB.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		var accountID, lastSessionID string
		var credentialGeneration int64
		err := tx.QueryRow(ctx, `
SELECT t.account_id, s.credential_generation, COALESCE(c.last_session_id, '')
FROM tunnel_connector_sessions AS s
JOIN tunnel_connectors AS c ON c.id = s.connector_id
JOIN tunnels AS t ON t.id = c.tunnel_id
WHERE s.id = $1 AND s.connector_id = $2 AND s.process_generation = $3
  AND c.tunnel_id = $4 AND t.deleted_at IS NULL
FOR UPDATE OF s, c`, ref.SessionID, ref.ConnectorID, int64(ref.ProcessGeneration), ref.TunnelID).Scan(&accountID, &credentialGeneration, &lastSessionID)
		if errors.Is(err, pgx.ErrNoRows) {
			// Disconnect is idempotent. A stale close after a replacement is a
			// harmless no-op, but an existing row must still prove its account.
			return nil
		}
		if err != nil {
			return err
		}
		if disconnect.AccountID != accountID {
			return ErrIdentityMismatch
		}
		// Exact identity in both predicates makes a stale close a harmless no-op
		// after a higher process generation has replaced this session.
		if _, err := tx.Exec(ctx, `
UPDATE tunnel_connector_sessions
SET state = CASE WHEN state = 'expired' THEN state ELSE 'disconnected' END,
    disconnected_at = COALESCE(disconnected_at, $1),
    disconnect_reason_code = COALESCE(disconnect_reason_code, $2)
WHERE id = $3 AND connector_id = $4 AND process_generation = $5`, now, string(disconnect.Reason), ref.SessionID, ref.ConnectorID, int64(ref.ProcessGeneration)); err != nil {
			return err
		}
		isCurrentSession := lastSessionID == ref.SessionID
		if isCurrentSession {
			_, err = tx.Exec(ctx, `
UPDATE tunnel_connectors
SET disconnect_reason_code = $1, updated_at = $2
WHERE id = $3 AND tunnel_id = $4 AND last_session_id = $5`, string(disconnect.Reason), now, ref.ConnectorID, ref.TunnelID, ref.SessionID)
			if err != nil {
				return err
			}
		}
		// Rotation targets carry their own exact proof/replacement session and
		// process bindings. They must be made recoverable even when session
		// creation has already advanced connector.last_session_id. Enrollment,
		// drain, and revoke lack that independent binding and remain restricted
		// to the connector's current session.
		return s.markDisconnectedOperations(ctx, tx, ref, credentialGeneration, accountID, disconnect.Reason, now, isCurrentSession)
	})
}

// markDisconnectedOperations moves only operations owned by the exact live
// connector session into the recoverable state. A stale close from an older
// process generation never changes a newer session's work. The transition and
// its audit row share this transaction so a restart worker can discover the
// same operation without relying on process memory.
func (s *SQLControlStore) markDisconnectedOperations(ctx context.Context, tx *db.Tx, ref SessionRef, credentialGeneration int64, accountID string, reason DisconnectReason, now time.Time, includeConnectorOperations bool) error {
	type operationRef struct {
		id, operationType, resourceType, resourceID string
	}
	operations := make([]operationRef, 0, 4)
	collect := func(query string, args ...any) error {
		rows, err := tx.Query(ctx, query, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var item operationRef
			if err := rows.Scan(&item.id, &item.operationType, &item.resourceType, &item.resourceID); err != nil {
				return err
			}
			operations = append(operations, item)
		}
		return rows.Err()
	}
	if includeConnectorOperations {
		if err := collect(`
SELECT o.id, o.operation_type, o.resource_kind, COALESCE(o.resource_id, '')
FROM operations AS o
JOIN tunnel_connector_credential_generations AS cg ON cg.source_operation_id = o.id
WHERE o.account_id = $1 AND o.resource_kind = 'connector' AND o.resource_id = $2
  AND o.operation_type = 'connector.enrollment.exchange'
  AND cg.connector_id = $2 AND cg.generation = $3
  AND o.state IN ('pending','running','uncertain')
FOR UPDATE OF o`, accountID, ref.ConnectorID, credentialGeneration); err != nil {
			return err
		}
		if err := collect(`
SELECT o.id, o.operation_type, o.resource_kind, COALESCE(o.resource_id, '')
FROM operations AS o
WHERE o.account_id = $1 AND o.resource_kind = 'connector' AND o.resource_id = $2
  AND o.operation_type IN ('connector.drain','connector.revoke')
  AND o.state IN ('pending','running','uncertain')
FOR UPDATE OF o`, accountID, ref.ConnectorID); err != nil {
			return err
		}
	}
	if err := collect(`
SELECT o.id, o.operation_type, o.resource_kind, COALESCE(o.resource_id, '')
FROM operations AS o
JOIN tunnel_connector_rotation_targets AS rt ON rt.operation_id = o.id
WHERE o.account_id = $1 AND o.resource_kind = 'tunnel' AND o.resource_id = $3
  AND o.operation_type = 'connector.credentials.rotate'
  AND rt.account_id = $1 AND rt.tunnel_id = $3 AND rt.connector_id = $2
  AND rt.state NOT IN ('revoked','failed')
  AND o.state IN ('pending','running','uncertain')
  AND (
    (rt.proof_session_id = $4 AND rt.proof_process_generation = $5)
    OR (rt.replacement_session_id = $4 AND rt.replacement_process_generation = $5)
    OR (rt.proof_session_id IS NULL AND rt.replacement_session_id IS NULL)
  )
FOR UPDATE OF o`, accountID, ref.ConnectorID, ref.TunnelID, ref.SessionID, int64(ref.ProcessGeneration)); err != nil {
		return err
	}
	seen := make(map[string]struct{}, len(operations))
	for _, operation := range operations {
		if operation.id == "" {
			continue
		}
		if _, ok := seen[operation.id]; ok {
			continue
		}
		seen[operation.id] = struct{}{}
		event := "connector.session_recovery_required"
		if operation.operationType == "connector.credentials.rotate" {
			event = "connector.credential_rotation_recovery_required"
		} else if operation.operationType == "connector.enrollment.exchange" {
			event = "connector.enrollment_recovery_required"
		} else if operation.operationType == "connector.drain" || operation.operationType == "connector.revoke" {
			event = "connector.drain_recovery_required"
		}
		result, err := tx.Exec(ctx, `
UPDATE operations
SET phase = CASE WHEN operation_type = 'connector.credentials.rotate' THEN 'connecting' ELSE 'draining' END,
    state = 'uncertain', progress = GREATEST(progress, 60), retrying = true,
    next_retry_at = $1, error_code = $2, outcome = 'uncertain', completed_at = NULL,
    updated_at = $1
WHERE id = $3 AND account_id = $4 AND state IN ('pending','running','uncertain')`, now, string(CodeStaleSession), operation.id, accountID)
		if err != nil {
			return err
		}
		if result.RowsAffected() != 1 {
			continue
		}
		metadata, err := json.Marshal(map[string]any{
			"session_id": ref.SessionID, "process_generation": ref.ProcessGeneration,
			"reason": reason, "credential_generation": credentialGeneration,
		})
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
INSERT INTO audit_events
  (id, actor_user_id, actor_type, event_type, resource_type, resource_id,
   idempotency_key, metadata, created_at, account_id, actor_id, change_type,
   outcome, correlation_id)
VALUES ($1, NULL, 'system', $2, $3, $4, $5, $6::jsonb, $7, $8,
	        'connector-control', $2, 'uncertain', $1)
			ON CONFLICT (id) DO NOTHING`, rotationAuditID(operation.id, ref.ConnectorID, event), event,
			operation.resourceType, operation.resourceID, operation.id+":"+ref.ConnectorID+":"+event, string(metadata), now, accountID); err != nil {
			return err
		}
	}
	return nil
}

func (s *SQLControlStore) RecordDrain(ctx context.Context, ref SessionRef, drain Drain, status DrainStatus, activeStreams uint32, code Code) error {
	if ctx == nil || s.valid() != nil || ref.Validate() != nil || drain.TunnelID != ref.TunnelID || drain.ConnectorID != ref.ConnectorID || drain.SessionID != ref.SessionID || drain.ProcessGeneration != ref.ProcessGeneration || activeStreams > MaxActiveStreams {
		return ErrInvalidInput
	}
	now := s.now()
	if err := drain.Validate(now); err != nil {
		return err
	}
	switch status {
	case DrainAccepted, DrainProgress, DrainCompleted, DrainForced, DrainRejected:
	default:
		return ErrInvalidInput
	}
	// The SQL boundary must enforce the same status/code/stream invariants as
	// the wire decoder. PersistentSession normally supplies a validated ACK,
	// but direct callers and retries must not be able to record a fabricated
	// terminal outcome or an unknown code.
	ack := DrainAck{
		AccountID: drain.AccountID, TunnelID: drain.TunnelID, ConnectorID: drain.ConnectorID,
		SessionID: drain.SessionID, ProcessGeneration: drain.ProcessGeneration,
		DrainID: drain.DrainID, Generation: drain.Generation, ContentHash: drain.ContentHash,
		Status: status, ActiveStreams: activeStreams, ForcedClose: status == DrainForced, Code: code,
	}
	if err := ack.Validate(now); err != nil {
		return err
	}
	return s.DB.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		accountID, err := s.lockSession(ctx, tx, ref, now)
		if err != nil {
			return err
		}
		if drain.AccountID != accountID {
			return ErrIdentityMismatch
		}
		storedHash, err := s.generationHash(ctx, tx, ref.TunnelID, drain.Generation)
		if err != nil {
			return err
		}
		if !configHashMatches(storedHash, Snapshot{ContentHash: drain.ContentHash}) {
			return ErrConfigHashCorrupt
		}
		operationType, operationState, err := s.lockDrainOperation(ctx, tx, ref, drain)
		if err != nil {
			return err
		}
		if operationState == "succeeded" || operationState == "failed" || operationState == "cancelled" {
			// Terminal operation rows are immutable. Duplicate acknowledgments are
			// safe no-ops and cannot resurrect admission or overwrite revoke state.
			return nil
		}
		var connectorDesiredState, connectorDrainState, connectorLastSession string
		if err := tx.QueryRow(ctx, `
SELECT desired_state, drain_state, COALESCE(last_session_id, '')
FROM tunnel_connectors
WHERE id = $1 AND tunnel_id = $2
FOR UPDATE`, ref.ConnectorID, ref.TunnelID).Scan(&connectorDesiredState, &connectorDrainState, &connectorLastSession); err != nil {
			return err
		}
		if connectorLastSession != ref.SessionID {
			return ErrStaleProcess
		}
		drainState := "draining"
		sessionState := "draining"
		if status == DrainCompleted {
			drainState = "drained"
		}
		if status == DrainForced {
			drainState = "forced_closed"
		}
		if status == DrainRejected {
			drainState = "accepting"
			sessionState = "ready"
		}
		terminalConnector := connectorDesiredState == "revoked" || connectorDrainState == "forced_closed"
		if terminalConnector {
			// Revocation/forced close is terminal. Do not let a late drain ACK
			// restore accepting/draining state. The exact operation still records
			// its own completion below.
			sessionState = "draining"
		}
		if _, err := tx.Exec(ctx, `
UPDATE tunnel_connector_sessions
SET state = $1
WHERE id = $2 AND connector_id = $3 AND process_generation = $4`, sessionState, ref.SessionID, ref.ConnectorID, int64(ref.ProcessGeneration)); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
UPDATE tunnel_connectors
SET desired_state = CASE
      WHEN desired_state = 'revoked' THEN desired_state
      WHEN drain_state = 'forced_closed' THEN desired_state
      WHEN $1 = 'accepting' THEN desired_state
      ELSE 'draining'
    END,
    drain_state = CASE
      WHEN desired_state = 'revoked' OR drain_state = 'forced_closed' THEN drain_state
      ELSE $1
    END,
    disconnect_reason_code = CASE WHEN $2 = '' THEN disconnect_reason_code ELSE $2 END,
    updated_at = $3
WHERE id = $4 AND tunnel_id = $5 AND last_session_id = $6`, drainState, string(code), now, ref.ConnectorID, ref.TunnelID, ref.SessionID); err != nil {
			return err
		}
		if err := s.updateDrainOperation(ctx, tx, ref, drain, now, status, activeStreams, code, operationType); err != nil {
			return err
		}
		return nil
	})
}

func (s *SQLControlStore) lockDrainOperation(ctx context.Context, tx *db.Tx, ref SessionRef, drain Drain) (string, string, error) {
	var operationType, state string
	if err := tx.QueryRow(ctx, `
SELECT operation_type, state
FROM operations
WHERE id = $1 AND account_id = $2 AND resource_kind = 'connector' AND resource_id = $3
  AND operation_type IN ('connector.drain', 'connector.revoke')
FOR UPDATE`, drain.DrainID, drain.AccountID, ref.ConnectorID).Scan(&operationType, &state); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", "", ErrOperationNotFound
		}
		return "", "", err
	}
	return operationType, state, nil
}

func (s *SQLControlStore) updateDrainOperation(ctx context.Context, tx *db.Tx, ref SessionRef, drain Drain, now time.Time, status DrainStatus, activeStreams uint32, code Code, operationType string) error {
	phase, state, progress, outcome := "draining", "running", 80, "changed"
	errorCode := string(code)
	completed := false
	switch status {
	case DrainCompleted:
		phase, state, progress, outcome, completed = "ready", "succeeded", 100, "changed", true
	case DrainForced:
		if operationType == "connector.revoke" {
			// A forced close is the intended terminal result of revoke. The
			// connector remains revoked while the operation is successful.
			phase, state, progress, outcome, completed = "ready", "succeeded", 100, "changed", true
		} else {
			phase, state, progress, outcome, completed = "failed", "failed", 100, "uncertain", true
			if errorCode == "" {
				errorCode = string(CodeDrainTimeout)
			}
		}
	case DrainRejected:
		phase, state, progress, outcome, completed = "failed", "failed", 100, "uncertain", true
		if errorCode == "" {
			errorCode = string(CodeDrainRejected)
		}
	}
	completedAt := "NULL"
	if completed {
		completedAt = "$5"
	}
	query := fmt.Sprintf(`UPDATE operations AS o
SET phase = $4, state = $6, progress = $7, outcome = $8,
    error_code = NULLIF($9, ''), completed_at = %s, updated_at = $5
WHERE o.id = $1 AND o.account_id = $2
  AND o.resource_kind = 'connector' AND o.resource_id = $3
  AND o.operation_type = $10
  AND o.state IN ('pending','running','uncertain')`, completedAt)
	result, err := tx.Exec(ctx, query, drain.DrainID, drain.AccountID, ref.ConnectorID, phase, now, state, progress, outcome, errorCode, operationType)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return ErrOperationNotFound
	}
	eventPrefix := "connector.drain"
	if operationType == "connector.revoke" {
		eventPrefix = "connector.revoke"
	}
	event := eventPrefix + "." + string(status)
	metadata, err := json.Marshal(map[string]any{
		"status": string(status), "active_streams": activeStreams,
		"code": errorCode, "session_id": ref.SessionID,
		"process_generation": ref.ProcessGeneration,
	})
	if err != nil {
		return err
	}
	if outcome == "" {
		outcome = "changed"
	}
	_, err = tx.Exec(ctx, `
INSERT INTO audit_events
  (id, actor_user_id, actor_type, event_type, resource_type, resource_id,
   idempotency_key, metadata, created_at, account_id, actor_id, change_type,
   outcome, correlation_id)
VALUES ($1, NULL, 'system', $2, 'connector', $3, $4, $5::jsonb, $6, $7,
	        'connector-control', $2, $8, $1)
ON CONFLICT (id) DO NOTHING`, rotationAuditID(drain.DrainID, ref.ConnectorID, event), event,
		ref.ConnectorID, drain.DrainID+":"+event, string(metadata), now, drain.AccountID, outcome)
	return err
}

// sqlRotationTarget is the database representation of one aggregate target.
// Nullable columns are deliberately scanned through database/sql scanners so
// recovery can distinguish a missing transition from an empty value.
type sqlRotationTarget struct {
	operationID, accountID, tunnelID, connectorID, hostID, targetSetHash string
	oldGeneration, newGeneration                                         int64
	state                                                                string
	oldIdentityKeyID, oldIdentityKeyThumbprint                           sql.NullString
	challengeNonce                                                       sql.NullString
	challengeIssuedAt, challengeExpiresAt, overlapUntil                  sql.NullTime
	newCredentialValidUntil                                              sql.NullTime
	proofSessionID                                                       sql.NullString
	proofProcessGeneration                                               sql.NullInt64
	newIdentityKeyID, newIdentityKeyThumbprint                           sql.NullString
	newPublicKey                                                         []byte
	newCredentialReference                                               sql.NullString
	replacementSessionID                                                 sql.NullString
	replacementProcessGeneration                                         sql.NullInt64
	configGeneration                                                     sql.NullInt64
	configContentHash                                                    []byte
	edgeReady, routeReady, originReady                                   sql.NullBool
	readyAt                                                              sql.NullTime
	revokeNonce                                                          sql.NullString
	revokeSessionID                                                      sql.NullString
	revokeProcessGeneration                                              sql.NullInt64
	revokeIssuedAt, revokeDeadline                                       sql.NullTime
	revokedAt                                                            sql.NullTime
	failureCode, failureMessage                                          sql.NullString
	createdAt, updatedAt                                                 time.Time
}

const rotationTargetSelect = `
SELECT operation_id, account_id, tunnel_id, connector_id, host_id,
       target_set_hash, old_credential_generation, new_credential_generation,
       state, old_identity_key_id, old_identity_key_thumbprint,
       challenge_nonce, challenge_issued_at, challenge_expires_at,
       overlap_until, new_credential_valid_until, proof_session_id,
       proof_process_generation, new_identity_key_id, new_identity_key_thumbprint,
       new_public_key, new_credential_reference, replacement_session_id,
       replacement_process_generation, config_generation, config_content_hash,
	       edge_ready, route_ready, origin_ready, ready_at, revoke_nonce,
	       revoke_session_id, revoke_process_generation, revoke_issued_at,
	       revoke_deadline, revoked_at, failure_code, failure_message,
       created_at, updated_at
FROM tunnel_connector_rotation_targets
WHERE operation_id = $1 AND account_id = $2 AND tunnel_id = $3 AND connector_id = $4`

type rowScanner interface {
	Scan(...any) error
}

func scanRotationTarget(row rowScanner, target *sqlRotationTarget) error {
	return row.Scan(
		&target.operationID, &target.accountID, &target.tunnelID, &target.connectorID, &target.hostID,
		&target.targetSetHash, &target.oldGeneration, &target.newGeneration, &target.state,
		&target.oldIdentityKeyID, &target.oldIdentityKeyThumbprint, &target.challengeNonce,
		&target.challengeIssuedAt, &target.challengeExpiresAt, &target.overlapUntil,
		&target.newCredentialValidUntil, &target.proofSessionID, &target.proofProcessGeneration,
		&target.newIdentityKeyID, &target.newIdentityKeyThumbprint, &target.newPublicKey,
		&target.newCredentialReference, &target.replacementSessionID,
		&target.replacementProcessGeneration, &target.configGeneration, &target.configContentHash,
		&target.edgeReady, &target.routeReady, &target.originReady, &target.readyAt,
		&target.revokeNonce, &target.revokeSessionID, &target.revokeProcessGeneration,
		&target.revokeIssuedAt, &target.revokeDeadline,
		&target.revokedAt,
		&target.failureCode, &target.failureMessage, &target.createdAt, &target.updatedAt,
	)
}

func (s *SQLControlStore) loadRotationTarget(ctx context.Context, tx *db.Tx, operationID, accountID, tunnelID, connectorID string, lock bool) (sqlRotationTarget, error) {
	query := rotationTargetSelect
	if lock {
		query += ` FOR UPDATE`
	}
	var target sqlRotationTarget
	if err := scanRotationTarget(tx.QueryRow(ctx, query, operationID, accountID, tunnelID, connectorID), &target); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return sqlRotationTarget{}, ErrOperationNotFound
		}
		return sqlRotationTarget{}, err
	}
	return target, nil
}

func rotationHashBytes(hash string) ([]byte, error) {
	if !hashPattern.MatchString(hash) {
		return nil, ErrInvalidInput
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(hash, "sha256:"))
	if err != nil || len(decoded) != sha256.Size {
		return nil, ErrInvalidInput
	}
	return decoded, nil
}

func rotationTargetFromSQL(target sqlRotationTarget) (RotationTarget, error) {
	if target.oldGeneration <= 0 || target.newGeneration <= 0 || uint64(target.oldGeneration) > uint64(^uint64(0)>>1) || uint64(target.newGeneration) > uint64(^uint64(0)>>1) {
		return RotationTarget{}, ErrInvalidInput
	}
	result := RotationTarget{ConnectorID: target.connectorID, HostID: target.hostID, OldCredentialGeneration: uint64(target.oldGeneration), NewCredentialGeneration: uint64(target.newGeneration)}
	if err := result.Validate(); err != nil {
		return RotationTarget{}, err
	}
	return result, nil
}

func rotationTime(value sql.NullTime) time.Time {
	if !value.Valid {
		return time.Time{}
	}
	return value.Time.UTC()
}

func rotationString(value sql.NullString) string {
	if !value.Valid {
		return ""
	}
	return value.String
}

func rotationUint(value sql.NullInt64) uint64 {
	if !value.Valid || value.Int64 <= 0 {
		return 0
	}
	return uint64(value.Int64)
}

func rotationBool(value sql.NullBool) bool { return value.Valid && value.Bool }

func (target sqlRotationTarget) target() (RotationTarget, error) {
	return rotationTargetFromSQL(target)
}

func (target sqlRotationTarget) challenge() (CredentialRotationChallenge, error) {
	item, err := target.target()
	if err != nil {
		return CredentialRotationChallenge{}, err
	}
	publicTarget := CredentialRotationChallenge{
		AccountID: target.accountID, TunnelID: target.tunnelID, OperationID: target.operationID,
		ConnectorID: target.connectorID, HostID: target.hostID, SessionID: rotationString(target.proofSessionID),
		ProcessGeneration: rotationUint(target.proofProcessGeneration), TargetSetHash: target.targetSetHash, Target: item,
		OldCredentialGeneration: item.OldCredentialGeneration, NewCredentialGeneration: item.NewCredentialGeneration,
		OldIdentityKeyID: rotationString(target.oldIdentityKeyID), OldIdentityKeyThumbprint: rotationString(target.oldIdentityKeyThumbprint),
		ChallengeNonce: rotationString(target.challengeNonce), IssuedAt: rotationTime(target.challengeIssuedAt),
		ExpiresAt: rotationTime(target.challengeExpiresAt), OverlapUntil: rotationTime(target.overlapUntil),
		NewCredentialValidUntil: rotationTime(target.newCredentialValidUntil),
	}
	if publicTarget.SessionID == "" {
		// The session that issued a challenge is represented by proof_session_id
		// only after proof acceptance. Load it from the target's durable challenge
		// column in callers that need the pre-proof state.
		return CredentialRotationChallenge{}, ErrOperationNotFound
	}
	return publicTarget, nil
}

func rotationAuditID(operationID, connectorID, event string) string {
	digest := sha256.Sum256([]byte(operationID + "\x00" + connectorID + "\x00" + event))
	return "aud-connector-" + hex.EncodeToString(digest[:])
}

func (s *SQLControlStore) recordRotationAudit(ctx context.Context, tx *db.Tx, target sqlRotationTarget, event, outcome string, metadata map[string]any, now time.Time) error {
	if metadata == nil {
		metadata = map[string]any{}
	}
	encoded, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
INSERT INTO audit_events
  (id, actor_user_id, actor_type, event_type, resource_type, resource_id,
   idempotency_key, metadata, created_at, account_id, actor_id, change_type,
   outcome, correlation_id)
VALUES ($1, NULL, 'system', $2, 'tunnel', $3, $4, $5::jsonb, $6, $7, 'connector-control', $2, $8, $1)
ON CONFLICT (id) DO NOTHING`, rotationAuditID(target.operationID, target.connectorID, event), event, target.tunnelID,
		target.operationID+":"+target.connectorID+":"+event, string(encoded), now, target.accountID, outcome)
	return err
}

func (s *SQLControlStore) lockRotationOperation(ctx context.Context, tx *db.Tx, plan RotationPlan) error {
	var accountID, resourceID, resourceKind, operationType, state string
	if err := tx.QueryRow(ctx, `
SELECT account_id, resource_id, resource_kind, operation_type, state
FROM operations WHERE id = $1 FOR UPDATE`, plan.OperationID).Scan(&accountID, &resourceID, &resourceKind, &operationType, &state); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrOperationNotFound
		}
		return err
	}
	if accountID != plan.AccountID || resourceID != plan.TunnelID || resourceKind != "tunnel" || operationType != "connector.credentials.rotate" || state == "cancelled" {
		return ErrIdentityMismatch
	}
	return nil
}

func (s *SQLControlStore) BeginCredentialRotation(ctx context.Context, plan RotationPlan) error {
	if ctx == nil || s.valid() != nil || plan.Validate() != nil {
		return ErrInvalidInput
	}
	if _, err := rotationHashBytes(plan.TargetSetHash); err != nil {
		return err
	}
	now := s.now()
	return s.DB.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		if err := s.lockRotationOperation(ctx, tx, plan); err != nil {
			return err
		}
		for _, item := range plan.Targets {
			if _, err := tx.Exec(ctx, `
INSERT INTO tunnel_connector_rotation_targets
  (operation_id, account_id, tunnel_id, connector_id, host_id, target_set_hash,
   old_credential_generation, new_credential_generation, state, created_at, updated_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'pending',$9,$9)
ON CONFLICT (operation_id, connector_id) DO NOTHING`, plan.OperationID, plan.AccountID, plan.TunnelID, item.ConnectorID, item.HostID, plan.TargetSetHash,
				int64(item.OldCredentialGeneration), int64(item.NewCredentialGeneration), now); err != nil {
				return err
			}
		}
		var count int
		var mismatched bool
		if err := tx.QueryRow(ctx, `
SELECT count(*), bool_or(target_set_hash <> $2)
FROM tunnel_connector_rotation_targets
WHERE operation_id = $1 AND account_id = $3 AND tunnel_id = $4`, plan.OperationID, plan.TargetSetHash, plan.AccountID, plan.TunnelID).Scan(&count, &mismatched); err != nil {
			return err
		}
		if count != len(plan.Targets) || mismatched {
			return ErrContentHashMismatch
		}
		if _, err := tx.Exec(ctx, `
UPDATE operations
SET phase = 'connecting', state = CASE WHEN state = 'succeeded' THEN state ELSE 'running' END,
    progress = GREATEST(progress, 60), outcome = 'changed', updated_at = $2
WHERE id = $1 AND account_id = $3`, plan.OperationID, now, plan.AccountID); err != nil {
			return err
		}
		var target sqlRotationTarget
		target.operationID, target.accountID, target.tunnelID = plan.OperationID, plan.AccountID, plan.TunnelID
		return s.recordRotationAudit(ctx, tx, target, "connector.credential_rotation_started", "changed", map[string]any{"target_count": len(plan.Targets), "target_set_hash": plan.TargetSetHash}, now)
	})
}

func (s *SQLControlStore) authorizeRotationSession(ctx context.Context, tx *db.Tx, challenge CredentialRotationChallenge, lock bool) error {
	if challenge.Validate(s.now()) != nil {
		return ErrInvalidInput
	}
	query := `
SELECT t.account_id, c.host_id, s.credential_generation, s.capabilities
FROM tunnel_connector_sessions AS s
JOIN tunnel_connectors AS c ON c.id = s.connector_id
JOIN tunnels AS t ON t.id = c.tunnel_id
WHERE s.id = $1 AND s.connector_id = $2 AND s.process_generation = $3
  AND s.credential_generation = $4 AND c.tunnel_id = $5 AND c.host_id = $6
  AND t.account_id = $7 AND t.deleted_at IS NULL
  AND c.revoked_at IS NULL AND c.desired_state <> 'revoked'
  AND s.state IN ('authenticating','ready','draining') AND s.lease_deadline > $8`
	if lock {
		query += ` FOR UPDATE OF s, c`
	}
	var accountID, hostID string
	var credentialGeneration int64
	var capabilities []string
	if err := tx.QueryRow(ctx, query, challenge.SessionID, challenge.ConnectorID, int64(challenge.ProcessGeneration), int64(challenge.OldCredentialGeneration), challenge.TunnelID, challenge.HostID, challenge.AccountID, s.now()).Scan(&accountID, &hostID, &credentialGeneration, &capabilities); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrSessionNotFound
		}
		return err
	}
	if accountID != challenge.AccountID || hostID != challenge.HostID || credentialGeneration != int64(challenge.OldCredentialGeneration) {
		return ErrIdentityMismatch
	}
	if !hasCapability(capabilities, CapabilityCredentialRotation) {
		return codeError(ErrCapabilityMissing, ReasonCapabilityMissing, false, errors.New("connector did not negotiate credential rotation"))
	}
	return nil
}

// AuthorizeCredentialRotationSession is called by the coordinator before it
// emits a challenge. It is intentionally a separate read-only boundary so a
// worker cannot challenge an arbitrary session or a connector that did not
// negotiate the rotation capability.
func (s *SQLControlStore) AuthorizeCredentialRotationSession(ctx context.Context, challenge CredentialRotationChallenge) error {
	if ctx == nil || s.valid() != nil {
		return ErrInvalidInput
	}
	return s.DB.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		return s.authorizeRotationSession(ctx, tx, challenge, true)
	})
}

func (s *SQLControlStore) authorizeRotationRecoverySession(ctx context.Context, tx *db.Tx, plan RotationPlan, target RotationTarget, ref SessionRef, credentialGeneration uint64, now time.Time) error {
	if plan.Validate() != nil || target.Validate() != nil || ref.Validate() != nil || ref.TunnelID != plan.TunnelID || ref.ConnectorID != target.ConnectorID || credentialGeneration == 0 {
		return ErrInvalidInput
	}
	var accountID, hostID string
	var storedGeneration int64
	var capabilities []string
	if err := tx.QueryRow(ctx, `
SELECT t.account_id, c.host_id, session.credential_generation, session.capabilities
FROM tunnel_connector_sessions AS session
JOIN tunnel_connectors AS c ON c.id = session.connector_id AND c.tunnel_id = $4
JOIN tunnels AS t ON t.id = c.tunnel_id AND t.account_id = $5
WHERE session.id = $1 AND session.connector_id = $2 AND session.process_generation = $3
  AND session.state IN ('authenticating','ready','draining') AND session.lease_deadline > $6
  AND c.host_id = $7 AND c.desired_state <> 'revoked' AND c.revoked_at IS NULL
FOR UPDATE OF session, c`, ref.SessionID, ref.ConnectorID, int64(ref.ProcessGeneration), ref.TunnelID, plan.AccountID, now, target.HostID).Scan(&accountID, &hostID, &storedGeneration, &capabilities); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrSessionNotFound
		}
		return err
	}
	if accountID != plan.AccountID || hostID != target.HostID || storedGeneration != int64(credentialGeneration) || !hasCapability(capabilities, CapabilityCredentialRotation) {
		return ErrIdentityMismatch
	}
	return nil
}

// ResetCredentialRotationInstall recovers the narrow window where proof was
// committed but the install frame was not received. Only a newer authenticated
// old-key session may discard the staged verifier and return the target to an
// expired challenged phase for a fresh nonce/proof exchange.
func (s *SQLControlStore) ResetCredentialRotationInstall(ctx context.Context, plan RotationPlan, target RotationTarget, ref SessionRef) error {
	if ctx == nil || s.valid() != nil {
		return ErrInvalidInput
	}
	now := s.now()
	return s.DB.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		row, err := s.loadRotationTarget(ctx, tx, plan.OperationID, plan.AccountID, plan.TunnelID, target.ConnectorID, true)
		if err != nil {
			return err
		}
		storedTarget, err := row.target()
		if err != nil || storedTarget != target || row.targetSetHash != plan.TargetSetHash {
			return ErrIdentityMismatch
		}
		if row.state != string(RotationTargetInstalled) || ref.ProcessGeneration <= rotationUint(row.proofProcessGeneration) {
			return ErrStaleProcess
		}
		if err := s.authorizeRotationRecoverySession(ctx, tx, plan, target, ref, target.OldCredentialGeneration, now); err != nil {
			return err
		}
		var liveReplacement int
		if err := tx.QueryRow(ctx, `
SELECT count(*) FROM tunnel_connector_sessions
WHERE connector_id = $1 AND credential_generation = $2
  AND state IN ('authenticating','ready','draining') AND lease_deadline > $3`, target.ConnectorID, int64(target.NewCredentialGeneration), now).Scan(&liveReplacement); err != nil {
			return err
		}
		if liveReplacement != 0 {
			return codeError(ErrSessionConflict, ReasonStaleGeneration, true, nil)
		}
		credential, err := tx.Exec(ctx, `
DELETE FROM tunnel_connector_credential_generations
WHERE connector_id = $1 AND tunnel_id = $2 AND generation = $3
  AND state = 'overlap' AND source_operation_id = $4`, target.ConnectorID, plan.TunnelID, int64(target.NewCredentialGeneration), plan.OperationID)
		if err != nil {
			return err
		}
		if credential.RowsAffected() != 1 {
			return ErrStaleProcess
		}
		result, err := tx.Exec(ctx, `
UPDATE tunnel_connector_rotation_targets
SET state = 'challenged', challenge_expires_at = GREATEST(challenge_issued_at + interval '1 microsecond', LEAST(challenge_expires_at, $1)),
    new_identity_key_id = NULL, new_identity_key_thumbprint = NULL,
    new_public_key = NULL, new_credential_reference = NULL,
    replacement_session_id = NULL, replacement_process_generation = NULL,
    config_generation = NULL, config_content_hash = NULL, edge_ready = NULL,
    route_ready = NULL, origin_ready = NULL, ready_at = NULL,
    revoke_nonce = NULL, revoke_session_id = NULL, revoke_process_generation = NULL,
    revoke_issued_at = NULL, revoke_deadline = NULL, updated_at = $1
WHERE operation_id = $2 AND account_id = $3 AND tunnel_id = $4
  AND connector_id = $5 AND state = 'installed'`, now, plan.OperationID, plan.AccountID, plan.TunnelID, target.ConnectorID)
		if err != nil {
			return err
		}
		if result.RowsAffected() != 1 {
			return ErrStaleProcess
		}
		row.state = string(RotationTargetChallenged)
		return s.recordRotationAudit(ctx, tx, row, "connector.credential_rotation_install_recovery_required", "uncertain", map[string]any{"session_id": ref.SessionID, "process_generation": ref.ProcessGeneration}, now)
	})
}

// RebindCredentialRotationRevoke safely moves an unexpired revoke to a newer
// authenticated replacement session after reconnect. Readiness remains bound
// to the session that proved it; only revoke delivery metadata changes.
func (s *SQLControlStore) RebindCredentialRotationRevoke(ctx context.Context, plan RotationPlan, target RotationTarget, ref SessionRef, nonce string, issuedAt, deadline time.Time) (CredentialRotationRevoke, error) {
	if ctx == nil || s.valid() != nil {
		return CredentialRotationRevoke{}, ErrInvalidInput
	}
	revoke := CredentialRotationRevoke{AccountID: plan.AccountID, TunnelID: plan.TunnelID, OperationID: plan.OperationID, ConnectorID: target.ConnectorID, HostID: target.HostID, SessionID: ref.SessionID, ProcessGeneration: ref.ProcessGeneration, TargetSetHash: plan.TargetSetHash, OldCredentialGeneration: target.OldCredentialGeneration, NewCredentialGeneration: target.NewCredentialGeneration, RevokeNonce: nonce, IssuedAt: issuedAt, Deadline: deadline}
	if err := revoke.Validate(s.now()); err != nil {
		return CredentialRotationRevoke{}, err
	}
	err := s.DB.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		row, err := s.loadRotationTarget(ctx, tx, plan.OperationID, plan.AccountID, plan.TunnelID, target.ConnectorID, true)
		if err != nil {
			return err
		}
		storedTarget, err := row.target()
		if err != nil || storedTarget != target || row.targetSetHash != plan.TargetSetHash {
			return ErrIdentityMismatch
		}
		if row.state != string(RotationTargetRevoking) || ref.ProcessGeneration <= rotationUint(row.revokeProcessGeneration) {
			return ErrStaleProcess
		}
		if err := s.authorizeRotationRecoverySession(ctx, tx, plan, target, ref, target.NewCredentialGeneration, s.now()); err != nil {
			return err
		}
		result, err := tx.Exec(ctx, `
UPDATE tunnel_connector_rotation_targets
SET revoke_nonce = $1, revoke_session_id = $2, revoke_process_generation = $3,
    revoke_issued_at = $4, revoke_deadline = $5, updated_at = $4
WHERE operation_id = $6 AND account_id = $7 AND tunnel_id = $8
  AND connector_id = $9 AND state = 'revoking'
  AND revoke_process_generation < $3`, nonce, ref.SessionID, int64(ref.ProcessGeneration), issuedAt, deadline, plan.OperationID, plan.AccountID, plan.TunnelID, target.ConnectorID)
		if err != nil {
			return err
		}
		if result.RowsAffected() != 1 {
			return ErrStaleProcess
		}
		row.revokeNonce = sql.NullString{String: nonce, Valid: true}
		row.revokeSessionID = sql.NullString{String: ref.SessionID, Valid: true}
		row.revokeProcessGeneration = sql.NullInt64{Int64: int64(ref.ProcessGeneration), Valid: true}
		return s.recordRotationAudit(ctx, tx, row, "connector.credential_rotation_revoke_rebound", "changed", map[string]any{"session_id": ref.SessionID, "process_generation": ref.ProcessGeneration}, issuedAt)
	})
	return revoke, err
}

// FailCredentialRotationTarget is the system-worker terminal path for a target
// whose immutable overlap window expired before readiness. It does not invent a
// connector acknowledgement and revokes any staged verifier in the same
// transaction.
func (s *SQLControlStore) FailCredentialRotationTarget(ctx context.Context, plan RotationPlan, target RotationTarget, code Code) error {
	if ctx == nil || s.valid() != nil || plan.Validate() != nil || target.Validate() != nil || !validCode(code) || code == "" {
		return ErrInvalidInput
	}
	now := s.now()
	return s.DB.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		row, err := s.loadRotationTarget(ctx, tx, plan.OperationID, plan.AccountID, plan.TunnelID, target.ConnectorID, true)
		if err != nil {
			return err
		}
		storedTarget, err := row.target()
		if err != nil || storedTarget != target || row.targetSetHash != plan.TargetSetHash {
			return ErrIdentityMismatch
		}
		if row.state == string(RotationTargetFailed) {
			if rotationString(row.failureCode) == string(code) {
				return nil
			}
			return ErrDurableReplay
		}
		if row.state == string(RotationTargetReady) || row.state == string(RotationTargetRevoking) || row.state == string(RotationTargetRevoked) {
			return ErrStaleProcess
		}
		if _, err := tx.Exec(ctx, `
UPDATE tunnel_connector_credential_generations
SET state = 'revoked', revoked_at = COALESCE(revoked_at, $1)
WHERE connector_id = $2 AND tunnel_id = $3 AND generation = $4
  AND source_operation_id = $5 AND state = 'overlap'`, now, target.ConnectorID, plan.TunnelID, int64(target.NewCredentialGeneration), plan.OperationID); err != nil {
			return err
		}
		result, err := tx.Exec(ctx, `
UPDATE tunnel_connector_rotation_targets
SET state = 'failed', failure_code = $1, failure_message = $2, updated_at = $3
WHERE operation_id = $4 AND account_id = $5 AND tunnel_id = $6
  AND connector_id = $7 AND state IN ('pending','challenged','installed')`, string(code), rotationFailureMessage(code), now, plan.OperationID, plan.AccountID, plan.TunnelID, target.ConnectorID)
		if err != nil {
			return err
		}
		if result.RowsAffected() != 1 {
			return ErrStaleProcess
		}
		operation, err := tx.Exec(ctx, `
UPDATE operations
SET phase = 'failed', state = 'failed', progress = 100, outcome = 'uncertain',
    error_code = $1, retrying = false, next_retry_at = NULL,
    completed_at = $2, updated_at = $2
WHERE id = $3 AND account_id = $4 AND resource_kind = 'tunnel'
  AND resource_id = $5 AND operation_type = 'connector.credentials.rotate'
  AND state IN ('pending','running','uncertain')`, string(code), now, plan.OperationID, plan.AccountID, plan.TunnelID)
		if err != nil {
			return err
		}
		if operation.RowsAffected() != 1 {
			return ErrOperationNotFound
		}
		row.state = string(RotationTargetFailed)
		row.failureCode = sql.NullString{String: string(code), Valid: true}
		return s.recordRotationAudit(ctx, tx, row, "connector.credential_rotation_failed", "uncertain", map[string]any{"code": code, "failure": rotationFailureMessage(code)}, now)
	})
}

func sameRotationChallenge(a, b CredentialRotationChallenge) bool {
	return a.AccountID == b.AccountID && a.TunnelID == b.TunnelID && a.OperationID == b.OperationID && a.ConnectorID == b.ConnectorID && a.HostID == b.HostID && a.SessionID == b.SessionID && a.ProcessGeneration == b.ProcessGeneration && a.TargetSetHash == b.TargetSetHash && a.Target == b.Target && a.OldCredentialGeneration == b.OldCredentialGeneration && a.NewCredentialGeneration == b.NewCredentialGeneration && a.OldIdentityKeyID == b.OldIdentityKeyID && a.OldIdentityKeyThumbprint == b.OldIdentityKeyThumbprint && a.ChallengeNonce == b.ChallengeNonce && a.IssuedAt.Equal(b.IssuedAt) && a.ExpiresAt.Equal(b.ExpiresAt) && a.OverlapUntil.Equal(b.OverlapUntil) && a.NewCredentialValidUntil.Equal(b.NewCredentialValidUntil)
}

func (s *SQLControlStore) RecordCredentialRotationChallenge(ctx context.Context, challenge CredentialRotationChallenge) error {
	if ctx == nil || s.valid() != nil {
		return ErrInvalidInput
	}
	now := s.now()
	if err := challenge.Validate(now); err != nil {
		return err
	}
	return s.DB.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		row, err := s.loadRotationTarget(ctx, tx, challenge.OperationID, challenge.AccountID, challenge.TunnelID, challenge.ConnectorID, true)
		if err != nil {
			return err
		}
		item, err := row.target()
		if err != nil {
			return err
		}
		if item != challenge.Target || row.targetSetHash != challenge.TargetSetHash || row.hostID != challenge.HostID {
			return ErrIdentityMismatch
		}
		if (row.overlapUntil.Valid && !row.overlapUntil.Time.Equal(challenge.OverlapUntil)) || (row.newCredentialValidUntil.Valid && !row.newCredentialValidUntil.Time.Equal(challenge.NewCredentialValidUntil)) {
			return ErrIdentityMismatch
		}
		if row.state == string(RotationTargetChallenged) {
			stored := CredentialRotationChallenge{AccountID: row.accountID, TunnelID: row.tunnelID, OperationID: row.operationID, ConnectorID: row.connectorID, HostID: row.hostID, SessionID: rotationString(row.proofSessionID), ProcessGeneration: rotationUint(row.proofProcessGeneration), TargetSetHash: row.targetSetHash, Target: item, OldCredentialGeneration: item.OldCredentialGeneration, NewCredentialGeneration: item.NewCredentialGeneration, OldIdentityKeyID: rotationString(row.oldIdentityKeyID), OldIdentityKeyThumbprint: rotationString(row.oldIdentityKeyThumbprint), ChallengeNonce: rotationString(row.challengeNonce), IssuedAt: rotationTime(row.challengeIssuedAt), ExpiresAt: rotationTime(row.challengeExpiresAt), OverlapUntil: rotationTime(row.overlapUntil), NewCredentialValidUntil: rotationTime(row.newCredentialValidUntil)}
			if sameRotationChallenge(stored, challenge) {
				return nil
			}
			if row.newPublicKey != nil || (row.challengeExpiresAt.Valid && row.challengeExpiresAt.Time.After(now)) {
				return ErrDurableReplay
			}
			// An uncompleted challenge may be renewed after its bounded expiry.
			// The target set and policy remain immutable, while the new nonce and
			// session generation replace only the expired challenge metadata.
			result, err := tx.Exec(ctx, `
UPDATE tunnel_connector_rotation_targets
SET old_identity_key_id = $1, old_identity_key_thumbprint = $2,
    challenge_nonce = $3, challenge_issued_at = $4, challenge_expires_at = $5,
    overlap_until = $6, new_credential_valid_until = $7,
    proof_session_id = $8, proof_process_generation = $9, updated_at = $10
WHERE operation_id = $11 AND account_id = $12 AND tunnel_id = $13
  AND connector_id = $14 AND state = 'challenged'`, challenge.OldIdentityKeyID, challenge.OldIdentityKeyThumbprint, challenge.ChallengeNonce, challenge.IssuedAt, challenge.ExpiresAt, challenge.OverlapUntil, challenge.NewCredentialValidUntil, challenge.SessionID, int64(challenge.ProcessGeneration), now, challenge.OperationID, challenge.AccountID, challenge.TunnelID, challenge.ConnectorID)
			if err != nil {
				return err
			}
			if result.RowsAffected() != 1 {
				return ErrStaleProcess
			}
			return s.recordRotationAudit(ctx, tx, row, "connector.credential_rotation_rechallenged", "changed", map[string]any{"target_set_hash": challenge.TargetSetHash}, now)
		}
		if row.state != string(RotationTargetPending) {
			return ErrStaleProcess
		}
		if err := s.authorizeRotationSession(ctx, tx, challenge, true); err != nil {
			return err
		}
		result, err := tx.Exec(ctx, `
UPDATE tunnel_connector_rotation_targets
SET state = 'challenged', old_identity_key_id = $1,
    old_identity_key_thumbprint = $2, challenge_nonce = $3,
    challenge_issued_at = $4, challenge_expires_at = $5,
    overlap_until = $6, new_credential_valid_until = $7,
    proof_session_id = $8, proof_process_generation = $9, updated_at = $10
WHERE operation_id = $11 AND account_id = $12 AND tunnel_id = $13
  AND connector_id = $14 AND state = 'pending'`, challenge.OldIdentityKeyID, challenge.OldIdentityKeyThumbprint, challenge.ChallengeNonce,
			challenge.IssuedAt, challenge.ExpiresAt, challenge.OverlapUntil, challenge.NewCredentialValidUntil, challenge.SessionID, int64(challenge.ProcessGeneration), now,
			challenge.OperationID, challenge.AccountID, challenge.TunnelID, challenge.ConnectorID)
		if err != nil {
			return err
		}
		if result.RowsAffected() != 1 {
			return ErrStaleProcess
		}
		row.state = string(RotationTargetChallenged)
		row.oldIdentityKeyID = sql.NullString{String: challenge.OldIdentityKeyID, Valid: true}
		row.oldIdentityKeyThumbprint = sql.NullString{String: challenge.OldIdentityKeyThumbprint, Valid: true}
		row.challengeNonce = sql.NullString{String: challenge.ChallengeNonce, Valid: true}
		row.challengeIssuedAt = sql.NullTime{Time: challenge.IssuedAt, Valid: true}
		row.challengeExpiresAt = sql.NullTime{Time: challenge.ExpiresAt, Valid: true}
		row.overlapUntil = sql.NullTime{Time: challenge.OverlapUntil, Valid: true}
		row.newCredentialValidUntil = sql.NullTime{Time: challenge.NewCredentialValidUntil, Valid: true}
		row.proofSessionID = sql.NullString{String: challenge.SessionID, Valid: true}
		row.proofProcessGeneration = sql.NullInt64{Int64: int64(challenge.ProcessGeneration), Valid: true}
		return s.recordRotationAudit(ctx, tx, row, "connector.credential_rotation_challenged", "changed", map[string]any{"target_set_hash": challenge.TargetSetHash, "new_credential_generation": challenge.NewCredentialGeneration}, now)
	})
}

func (s *SQLControlStore) verifyRotationProofInTx(ctx context.Context, tx *db.Tx, proof CredentialRotationProof, now, replayExpiresAt time.Time) error {
	payload, err := CredentialRotationProofPayload(proof)
	if err != nil {
		return err
	}
	oldSignature, err := DecodeProof(proof.OldSignedProof)
	if err != nil {
		return err
	}
	material, err := s.loadProofMaterial(ctx, tx, proof.AccountID, proof.TunnelID, proof.ConnectorID, proof.HostID, proof.OldCredentialGeneration, now, true)
	if err != nil {
		return err
	}
	oldKey, err := material.proofKey(proof.OldIdentityKeyID, proof.OldIdentityKeyThumbprint)
	if err != nil {
		return err
	}
	if err := verifyTranscript(payload, payload, oldSignature, oldKey); err != nil {
		return err
	}
	newSignature, err := DecodeProof(proof.NewSignedProof)
	if err != nil {
		return err
	}
	newKey, err := decodeRotationPublicKey(proof.NewPublicKey)
	if err != nil || !ed25519.Verify(newKey, payload, newSignature) {
		return ErrAuthenticationFailed
	}
	// Rotation proofs use the challenge nonce as their replay identity. Reserve
	// it only after both old-key authorization and new-key proof of possession
	// succeed, while the same locked target/proof-material transaction is still
	// open. The challenge expiry keeps the replay row bounded and prevents a
	// later operation from reusing a transcript indefinitely.
	return reserveControlReplay(ctx, tx, proof.AccountID, proof.TunnelID, proof.ConnectorID, proof.OldCredentialGeneration, "rotation", proof.ChallengeNonce, payload, replayExpiresAt, now)
}

func rotationCredentialID(operationID, connectorID string, generation uint64) string {
	digest := sha256.Sum256([]byte(operationID + "\x00" + connectorID + "\x00" + fmt.Sprint(generation)))
	return "cred-rotation-" + hex.EncodeToString(digest[:])
}

func (s *SQLControlStore) RecordCredentialRotationProof(ctx context.Context, challenge CredentialRotationChallenge, proof CredentialRotationProof, install CredentialRotationInstall) error {
	if ctx == nil || s.valid() != nil {
		return ErrInvalidInput
	}
	now := s.now()
	if err := challenge.Validate(now); err != nil {
		return err
	}
	if err := proof.Validate(now); err != nil {
		return err
	}
	if err := install.Validate(now); err != nil {
		return err
	}
	publicKey, err := decodeRotationPublicKey(proof.NewPublicKey)
	if err != nil {
		return err
	}
	return s.DB.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		row, err := s.loadRotationTarget(ctx, tx, proof.OperationID, proof.AccountID, proof.TunnelID, proof.ConnectorID, true)
		if err != nil {
			return err
		}
		item, err := row.target()
		if err != nil {
			return err
		}
		storedChallenge, err := row.challenge()
		if err != nil {
			return err
		}
		if row.state != string(RotationTargetChallenged) || item != challenge.Target || !sameRotationChallenge(storedChallenge, challenge) || !rotationProofMatchesChallenge(proof, challenge, item) || proof.NewCredentialValidUntil != challenge.NewCredentialValidUntil || install.HostID != proof.HostID || install.NewCredentialValidUntil != proof.NewCredentialValidUntil {
			return ErrStaleProcess
		}
		if err := s.authorizeRotationSession(ctx, tx, challenge, true); err != nil {
			return err
		}
		if err := s.verifyRotationProofInTx(ctx, tx, proof, now, storedChallenge.ExpiresAt); err != nil {
			return codeError(ErrAuthenticationFailed, ReasonAuthentication, false, err)
		}
		// Proof acceptance stages the replacement verifier but does not switch
		// the connector's authoritative credential yet. The old generation
		// remains active until the replacement session reports full readiness.
		// This preserves the last-known-good control path if installation or
		// readiness fails after the new key has been recorded.
		if _, err := tx.Exec(ctx, `
		INSERT INTO tunnel_connector_credential_generations
		  (id, connector_id, tunnel_id, generation, credential_reference,
		   credential_thumbprint, verifier_algorithm, verifier_public_key, state,
		   valid_until, created_at, source_operation_id)
		VALUES ($1,$2,$3,$4,$5,$6,'ed25519',$7,'overlap',$8,$9,$10)
		ON CONFLICT (connector_id, generation) DO NOTHING`, rotationCredentialID(proof.OperationID, proof.ConnectorID, proof.NewCredentialGeneration), proof.ConnectorID, proof.TunnelID, int64(proof.NewCredentialGeneration), proof.NewCredentialReference, proof.NewIdentityKeyThumbprint, publicKey, proof.NewCredentialValidUntil, now, proof.OperationID); err != nil {
			return err
		}
		var storedKey []byte
		var storedReference, storedThumbprint, sourceOperation, storedState string
		var storedValidUntil time.Time
		if err := tx.QueryRow(ctx, `
SELECT verifier_public_key, credential_reference, credential_thumbprint, COALESCE(source_operation_id, ''), state, valid_until
FROM tunnel_connector_credential_generations
WHERE connector_id = $1 AND tunnel_id = $2 AND generation = $3`, proof.ConnectorID, proof.TunnelID, int64(proof.NewCredentialGeneration)).Scan(&storedKey, &storedReference, &storedThumbprint, &sourceOperation, &storedState, &storedValidUntil); err != nil {
			return err
		}
		if !bytes.Equal(storedKey, publicKey) || storedReference != proof.NewCredentialReference || storedThumbprint != proof.NewIdentityKeyThumbprint || sourceOperation != proof.OperationID || storedState != "overlap" || !storedValidUntil.Equal(proof.NewCredentialValidUntil) {
			return ErrContentHashMismatch
		}
		result, err := tx.Exec(ctx, `
UPDATE tunnel_connector_rotation_targets
SET state = 'installed', proof_session_id = $1, proof_process_generation = $2,
    new_identity_key_id = $3, new_identity_key_thumbprint = $4,
    new_public_key = $5, new_credential_reference = $6,
    new_credential_valid_until = $7, updated_at = $8
WHERE operation_id = $9 AND account_id = $10 AND tunnel_id = $11
		  AND connector_id = $12 AND state = 'challenged'`, proof.SessionID, int64(proof.ProcessGeneration), proof.NewIdentityKeyID, proof.NewIdentityKeyThumbprint, publicKey, proof.NewCredentialReference, proof.NewCredentialValidUntil, now, proof.OperationID, proof.AccountID, proof.TunnelID, proof.ConnectorID)
		if err != nil {
			return err
		}
		if result.RowsAffected() != 1 {
			return ErrStaleProcess
		}
		operationResult, err := tx.Exec(ctx, `
UPDATE operations SET phase = 'connecting', state = 'running', progress = GREATEST(progress, 70), updated_at = $2
WHERE id = $1 AND account_id = $3 AND resource_kind = 'tunnel' AND resource_id = $4
	  AND operation_type = 'connector.credentials.rotate' AND state IN ('pending','running','uncertain')`, proof.OperationID, now, proof.AccountID, proof.TunnelID)
		if err != nil {
			return err
		}
		if operationResult.RowsAffected() != 1 {
			return ErrOperationNotFound
		}
		row.state = string(RotationTargetInstalled)
		return s.recordRotationAudit(ctx, tx, row, "connector.credential_rotation_installed", "changed", map[string]any{"new_credential_generation": proof.NewCredentialGeneration, "replacement_process_generation": install.ReplacementProcessGeneration}, now)
	})
}

// VerifyRotationOldProof performs the old-key lookup through the same durable
// connector/host/generation boundary used by authentication. It is useful to
// callers that need a verifier callback for RotationCoordinator; the SQL write
// path still verifies again under its locked transaction.
func (s *SQLControlStore) VerifyRotationOldProof(ctx context.Context, proof CredentialRotationProof, payload, signature []byte) error {
	if ctx == nil || s.valid() != nil {
		return ErrAuthenticationFailed
	}
	if err := proof.Validate(s.now()); err != nil {
		return err
	}
	expected, err := CredentialRotationProofPayload(proof)
	if err != nil {
		return err
	}
	now := s.now()
	return s.DB.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		material, err := s.loadProofMaterial(ctx, tx, proof.AccountID, proof.TunnelID, proof.ConnectorID, proof.HostID, proof.OldCredentialGeneration, now, true)
		if err != nil {
			return err
		}
		key, err := material.proofKey(proof.OldIdentityKeyID, proof.OldIdentityKeyThumbprint)
		if err != nil {
			return err
		}
		return verifyTranscript(expected, payload, signature, key)
	})
}

func (s *SQLControlStore) RecordCredentialRotationReady(ctx context.Context, ready CredentialRotationReady) error {
	if ctx == nil || s.valid() != nil {
		return ErrInvalidInput
	}
	now := s.now()
	if err := ready.Validate(now); err != nil {
		return err
	}
	return s.DB.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		row, err := s.loadRotationTarget(ctx, tx, ready.OperationID, ready.AccountID, ready.TunnelID, ready.ConnectorID, true)
		if err != nil {
			return err
		}
		item, err := row.target()
		if err != nil {
			return err
		}
		if row.state != string(RotationTargetInstalled) || row.hostID != ready.HostID || item.OldCredentialGeneration != ready.OldCredentialGeneration || item.NewCredentialGeneration != ready.NewCredentialGeneration || row.targetSetHash != ready.TargetSetHash || ready.ProcessGeneration < rotationUint(row.proofProcessGeneration)+1 || rotationString(row.newIdentityKeyID) != ready.NewIdentityKeyID || rotationString(row.newIdentityKeyThumbprint) != ready.NewIdentityKeyThumbprint || rotationString(row.newCredentialReference) != ready.NewCredentialReference || !bytes.Equal(row.newPublicKey, mustRotationPublicKey(ready.NewPublicKey)) || !rotationTime(row.newCredentialValidUntil).Equal(ready.NewCredentialValidUntil) {
			return ErrIdentityMismatch
		}
		if !row.overlapUntil.Valid || !row.overlapUntil.Time.After(now) {
			return ErrCredentialExpired
		}
		var accountID, hostID, state string
		var credentialGeneration, processGeneration int64
		if err := tx.QueryRow(ctx, `
SELECT t.account_id, c.host_id, s.state, s.credential_generation, s.process_generation
FROM tunnel_connector_sessions AS s
JOIN tunnel_connectors AS c ON c.id = s.connector_id
JOIN tunnels AS t ON t.id = c.tunnel_id
WHERE s.id = $1 AND s.connector_id = $2 AND s.process_generation = $3
  AND s.credential_generation = $4 AND c.tunnel_id = $5 AND c.host_id = $6
  AND t.account_id = $7 AND t.deleted_at IS NULL
  AND s.state IN ('authenticating','ready','draining') AND s.lease_deadline > $8
FOR UPDATE OF s, c`, ready.SessionID, ready.ConnectorID, int64(ready.ProcessGeneration), int64(ready.NewCredentialGeneration), ready.TunnelID, ready.HostID, ready.AccountID, now).Scan(&accountID, &hostID, &state, &credentialGeneration, &processGeneration); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrSessionNotFound
			}
			return err
		}
		if accountID != ready.AccountID || hostID != ready.HostID || state == "" || credentialGeneration != int64(ready.NewCredentialGeneration) || processGeneration != int64(ready.ProcessGeneration) {
			return ErrIdentityMismatch
		}
		storedHash, err := s.generationHash(ctx, tx, ready.TunnelID, ready.ConfigGeneration)
		if err != nil {
			return err
		}
		if !configHashMatches(storedHash, Snapshot{ContentHash: ready.ConfigContentHash}) {
			return ErrConfigHashCorrupt
		}
		// Demote the old generation first. The partial unique index permits only
		// one active generation, and both changes are hidden until this transaction
		// commits, so readers never observe a connector without an active key.
		oldCredential, err := tx.Exec(ctx, `
			UPDATE tunnel_connector_credential_generations
		SET state = 'overlap', valid_until = $1
		WHERE connector_id = $2 AND tunnel_id = $3 AND generation = $4
		  AND state = 'active' AND valid_until > $5`, rotationTime(row.overlapUntil), ready.ConnectorID, ready.TunnelID, int64(ready.OldCredentialGeneration), now)
		if err != nil {
			return err
		}
		if oldCredential.RowsAffected() != 1 {
			return ErrStaleProcess
		}
		newCredential, err := tx.Exec(ctx, `
			UPDATE tunnel_connector_credential_generations
			SET state = 'active'
			WHERE connector_id = $1 AND tunnel_id = $2 AND generation = $3
			  AND state = 'overlap' AND valid_until = $4 AND valid_until > $5`, ready.ConnectorID, ready.TunnelID, int64(ready.NewCredentialGeneration), ready.NewCredentialValidUntil, now)
		if err != nil {
			return err
		}
		if newCredential.RowsAffected() != 1 {
			return ErrStaleProcess
		}
		result, err := tx.Exec(ctx, `
UPDATE tunnel_connector_rotation_targets
SET state = 'ready', replacement_session_id = $1,
    replacement_process_generation = $2, config_generation = $3,
    config_content_hash = $4, edge_ready = TRUE, route_ready = TRUE,
    origin_ready = TRUE, ready_at = $5, updated_at = $5
WHERE operation_id = $6 AND account_id = $7 AND tunnel_id = $8
	  AND connector_id = $9 AND state = 'installed'`, ready.SessionID, int64(ready.ProcessGeneration), int64(ready.ConfigGeneration), storedHash, ready.ReadyAt, ready.OperationID, ready.AccountID, ready.TunnelID, ready.ConnectorID)
		if err != nil {
			return err
		}
		if result.RowsAffected() != 1 {
			return ErrStaleProcess
		}
		sessionResult, err := tx.Exec(ctx, `
UPDATE tunnel_connector_sessions
SET state = 'ready', ready_at = $1, applied_config_generation = GREATEST(applied_config_generation, $2)
WHERE id = $3 AND connector_id = $4 AND process_generation = $5
	  AND credential_generation = $6 AND state IN ('authenticating','ready','draining') AND lease_deadline > $7`, ready.ReadyAt, int64(ready.ConfigGeneration), ready.SessionID, ready.ConnectorID, int64(ready.ProcessGeneration), int64(ready.NewCredentialGeneration), now)
		if err != nil {
			return err
		}
		if sessionResult.RowsAffected() != 1 {
			return ErrStaleProcess
		}
		connectorResult, err := tx.Exec(ctx, `
UPDATE tunnel_connectors
SET credential_reference = $1, credential_thumbprint = $2, rotation_generation = $3,
    ready_at = $4, last_applied_config_generation = GREATEST(last_applied_config_generation, $5),
	updated_at = $4
WHERE id = $6 AND tunnel_id = $7 AND host_id = $8
  AND rotation_generation = $9 AND desired_state <> 'revoked' AND drain_state <> 'forced_closed'`, ready.NewCredentialReference, ready.NewIdentityKeyThumbprint, int64(ready.NewCredentialGeneration), ready.ReadyAt, int64(ready.ConfigGeneration), ready.ConnectorID, ready.TunnelID, ready.HostID, int64(ready.OldCredentialGeneration))
		if err != nil {
			return err
		}
		if connectorResult.RowsAffected() != 1 {
			return ErrStaleProcess
		}
		row.state = string(RotationTargetReady)
		return s.recordRotationAudit(ctx, tx, row, "connector.credential_rotation_ready", "changed", map[string]any{"new_credential_generation": ready.NewCredentialGeneration, "config_generation": ready.ConfigGeneration}, now)
	})
}

func mustRotationPublicKey(value string) []byte {
	key, err := decodeRotationPublicKey(value)
	if err != nil {
		return nil
	}
	return key
}

func (s *SQLControlStore) RecordCredentialRotationRevoke(ctx context.Context, revoke CredentialRotationRevoke) error {
	if ctx == nil || s.valid() != nil {
		return ErrInvalidInput
	}
	now := s.now()
	if err := revoke.Validate(now); err != nil {
		return err
	}
	return s.DB.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		row, err := s.loadRotationTarget(ctx, tx, revoke.OperationID, revoke.AccountID, revoke.TunnelID, revoke.ConnectorID, true)
		if err != nil {
			return err
		}
		item, err := row.target()
		if err != nil {
			return err
		}
		if row.hostID != revoke.HostID || row.targetSetHash != revoke.TargetSetHash || item.OldCredentialGeneration != revoke.OldCredentialGeneration || item.NewCredentialGeneration != revoke.NewCredentialGeneration || rotationString(row.replacementSessionID) != revoke.SessionID || rotationUint(row.replacementProcessGeneration) != revoke.ProcessGeneration {
			return ErrIdentityMismatch
		}
		if row.state == string(RotationTargetRevoking) {
			if rotationString(row.revokeNonce) == revoke.RevokeNonce && rotationString(row.revokeSessionID) == revoke.SessionID && rotationUint(row.revokeProcessGeneration) == revoke.ProcessGeneration && rotationTime(row.revokeDeadline).Equal(revoke.Deadline) {
				return nil
			}
			return ErrDurableReplay
		}
		if row.state != string(RotationTargetReady) {
			return ErrStaleProcess
		}
		var incomplete int
		if err := tx.QueryRow(ctx, `
SELECT count(*) FROM tunnel_connector_rotation_targets
WHERE operation_id = $1 AND account_id = $2 AND tunnel_id = $3
  AND state NOT IN ('ready','revoking','revoked')`, revoke.OperationID, revoke.AccountID, revoke.TunnelID).Scan(&incomplete); err != nil {
			return err
		}
		if incomplete != 0 {
			return codeError(ErrCredentialRotationNotReady, ReasonCredentialRotation, true, nil)
		}
		result, err := tx.Exec(ctx, `
UPDATE tunnel_connector_rotation_targets
	SET state = 'revoking', revoke_nonce = $1, revoke_session_id = $2,
	    revoke_process_generation = $3, revoke_issued_at = $4,
	    revoke_deadline = $5, updated_at = $6
	WHERE operation_id = $7 AND account_id = $8 AND tunnel_id = $9
			  AND connector_id = $10 AND state = 'ready'`, revoke.RevokeNonce, revoke.SessionID, int64(revoke.ProcessGeneration), revoke.IssuedAt, revoke.Deadline, now, revoke.OperationID, revoke.AccountID, revoke.TunnelID, revoke.ConnectorID)
		if err != nil {
			return err
		}
		if result.RowsAffected() != 1 {
			return ErrStaleProcess
		}
		row.state = string(RotationTargetRevoking)
		return s.recordRotationAudit(ctx, tx, row, "connector.credential_rotation_revoke_requested", "changed", map[string]any{"old_credential_generation": revoke.OldCredentialGeneration, "new_credential_generation": revoke.NewCredentialGeneration}, now)
	})
}

func (s *SQLControlStore) updateRotationOperation(ctx context.Context, tx *db.Tx, ack CredentialRotationAck, failed bool, now time.Time) error {
	if failed {
		result, err := tx.Exec(ctx, `
UPDATE operations
SET phase = 'failed', state = 'failed', progress = 100,
    outcome = 'uncertain', error_code = $1, completed_at = $2, updated_at = $2
WHERE id = $3 AND account_id = $4 AND resource_kind = 'tunnel'
  AND resource_id = $5 AND operation_type = 'connector.credentials.rotate'
  AND state IN ('pending','running','uncertain')`, string(ack.Code), now, ack.OperationID, ack.AccountID, ack.TunnelID)
		if err != nil {
			return err
		}
		if result.RowsAffected() != 1 {
			return ErrOperationNotFound
		}
		return nil
	}
	var total, revoked int
	if err := tx.QueryRow(ctx, `
SELECT count(*), count(*) FILTER (WHERE state = 'revoked')
FROM tunnel_connector_rotation_targets
WHERE operation_id = $1 AND account_id = $2 AND tunnel_id = $3`, ack.OperationID, ack.AccountID, ack.TunnelID).Scan(&total, &revoked); err != nil {
		return err
	}
	if total == 0 {
		return ErrOperationNotFound
	}
	if revoked == total {
		result, err := tx.Exec(ctx, `
UPDATE operations SET phase = 'ready', state = 'succeeded', progress = 100,
    outcome = 'changed', completed_at = $1, updated_at = $1
WHERE id = $2 AND account_id = $3 AND resource_kind = 'tunnel'
  AND resource_id = $4 AND operation_type = 'connector.credentials.rotate'
	  AND state IN ('pending','running','uncertain')`, now, ack.OperationID, ack.AccountID, ack.TunnelID)
		if err != nil {
			return err
		}
		if result.RowsAffected() != 1 {
			return ErrOperationNotFound
		}
		return nil
	}
	progress := int16(70)
	if total > 0 {
		progress = int16(70 + (25 * revoked / total))
	}
	result, err := tx.Exec(ctx, `
UPDATE operations SET phase = 'connecting', state = 'running', progress = GREATEST(progress, $1), updated_at = $2
WHERE id = $3 AND account_id = $4 AND resource_kind = 'tunnel'
  AND resource_id = $5 AND operation_type = 'connector.credentials.rotate'
	  AND state IN ('pending','running','uncertain')`, progress, now, ack.OperationID, ack.AccountID, ack.TunnelID)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return ErrOperationNotFound
	}
	return nil
}

func (s *SQLControlStore) RecordCredentialRotationResult(ctx context.Context, ack CredentialRotationAck, summary RotationSummary) error {
	if ctx == nil || s.valid() != nil {
		return ErrInvalidInput
	}
	now := s.now()
	if err := ack.Validate(); err != nil {
		return err
	}
	if summary.AccountID != ack.AccountID || summary.TunnelID != ack.TunnelID || summary.OperationID != ack.OperationID || summary.TargetSetHash != ack.TargetSetHash {
		return ErrIdentityMismatch
	}
	return s.DB.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		row, err := s.loadRotationTarget(ctx, tx, ack.OperationID, ack.AccountID, ack.TunnelID, ack.ConnectorID, true)
		if err != nil {
			return err
		}
		item, err := row.target()
		if err != nil {
			return err
		}
		if row.hostID != ack.HostID || row.targetSetHash != ack.TargetSetHash || item.OldCredentialGeneration != ack.OldCredentialGeneration || item.NewCredentialGeneration != ack.NewCredentialGeneration {
			return ErrIdentityMismatch
		}
		if err := s.validateRotationSummary(ctx, tx, ack, summary); err != nil {
			return err
		}
		if row.state == string(RotationTargetRevoked) || row.state == string(RotationTargetFailed) {
			// A duplicate terminal result is safe only when it describes the
			// exact durable aggregate state. The summary validation above binds
			// the retry to the same target set and operation before this no-op.
			return nil
		}
		if ack.Status == RotationAckRejected || ack.Status == RotationAckFailed {
			if !rotationResultAckMatchesTarget(row, ack) {
				return ErrIdentityMismatch
			}
			result, err := tx.Exec(ctx, `
UPDATE tunnel_connector_rotation_targets
SET state = 'failed', failure_code = $1, failure_message = NULLIF($2, ''), updated_at = $3
WHERE operation_id = $4 AND account_id = $5 AND tunnel_id = $6
			  AND connector_id = $7 AND state NOT IN ('revoked','failed')`, string(ack.Code), rotationFailureMessage(ack.Code), now, ack.OperationID, ack.AccountID, ack.TunnelID, ack.ConnectorID)
			if err != nil {
				return err
			}
			if result.RowsAffected() != 1 {
				return ErrStaleProcess
			}
			row.state = string(RotationTargetFailed)
			row.failureCode = sql.NullString{String: string(ack.Code), Valid: true}
			if err := s.updateRotationOperation(ctx, tx, ack, true, now); err != nil {
				return err
			}
			return s.recordRotationAudit(ctx, tx, row, "connector.credential_rotation_failed", "uncertain", map[string]any{"code": ack.Code, "failure": rotationFailureMessage(ack.Code)}, now)
		}
		if ack.Status != RotationAckRevoked || row.state != string(RotationTargetRevoking) || ack.SessionID != rotationString(row.replacementSessionID) || ack.ProcessGeneration != rotationUint(row.replacementProcessGeneration) {
			return ErrStaleProcess
		}
		var connectorState, drainState, sessionState string
		var sessionCredentialGeneration int64
		var sessionLeaseDeadline time.Time
		if err := tx.QueryRow(ctx, `
SELECT c.desired_state, c.drain_state, s.state, s.credential_generation, s.lease_deadline
FROM tunnel_connectors AS c
JOIN tunnel_connector_sessions AS s ON s.id = $1 AND s.connector_id = c.id AND s.process_generation = $2
WHERE c.id = $3 AND c.tunnel_id = $4 AND c.host_id = $5
FOR UPDATE OF c, s`, ack.SessionID, int64(ack.ProcessGeneration), ack.ConnectorID, ack.TunnelID, ack.HostID).Scan(&connectorState, &drainState, &sessionState, &sessionCredentialGeneration, &sessionLeaseDeadline); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrSessionNotFound
			}
			return err
		}
		if connectorState == "revoked" || drainState == "forced_closed" || sessionState != "ready" && sessionState != "draining" || !sessionLeaseDeadline.After(now) || sessionCredentialGeneration != int64(ack.NewCredentialGeneration) {
			return ErrStaleProcess
		}
		result, err := tx.Exec(ctx, `
UPDATE tunnel_connector_rotation_targets
SET state = 'revoked', revoked_at = $1, updated_at = $1
WHERE operation_id = $2 AND account_id = $3 AND tunnel_id = $4
	  AND connector_id = $5 AND state = 'revoking'`, now, ack.OperationID, ack.AccountID, ack.TunnelID, ack.ConnectorID)
		if err != nil {
			return err
		}
		if result.RowsAffected() != 1 {
			return ErrStaleProcess
		}
		oldCredential, err := tx.Exec(ctx, `
UPDATE tunnel_connector_credential_generations
SET state = 'revoked', revoked_at = COALESCE(revoked_at, $1)
WHERE connector_id = $2 AND tunnel_id = $3 AND generation = $4
	  AND state = 'overlap'`, now, ack.ConnectorID, ack.TunnelID, int64(ack.OldCredentialGeneration))
		if err != nil {
			return err
		}
		if oldCredential.RowsAffected() != 1 {
			return ErrStaleProcess
		}
		row.state = string(RotationTargetRevoked)
		if err := s.updateRotationOperation(ctx, tx, ack, false, now); err != nil {
			return err
		}
		return s.recordRotationAudit(ctx, tx, row, "connector.credential_rotation_revoked", "changed", map[string]any{"old_credential_generation": ack.OldCredentialGeneration, "new_credential_generation": ack.NewCredentialGeneration}, now)
	})
}

// validateRotationSummary independently checks the aggregate projection sent
// with a per-target result. The coordinator normally constructs this summary,
// but the SQL boundary must not trust it: a caller could otherwise omit a
// connector, claim a different target set, or advance an unrelated target's
// state while still presenting a validly shaped ACK.
func (s *SQLControlStore) validateRotationSummary(ctx context.Context, tx *db.Tx, ack CredentialRotationAck, summary RotationSummary) error {
	if summary.Status != RotationAggregatePending && summary.Status != RotationAggregateSucceeded && summary.Status != RotationAggregateFailed {
		return ErrInvalidInput
	}
	rows, err := tx.Query(ctx, strings.Replace(rotationTargetSelect, " AND connector_id = $4", "", 1)+` ORDER BY connector_id`, ack.OperationID, ack.AccountID, ack.TunnelID)
	if err != nil {
		return err
	}
	defer rows.Close()
	stored := make(map[string]sqlRotationTarget)
	for rows.Next() {
		var target sqlRotationTarget
		if err := scanRotationTarget(rows, &target); err != nil {
			return err
		}
		if target.accountID != ack.AccountID || target.tunnelID != ack.TunnelID || target.targetSetHash != ack.TargetSetHash {
			return ErrContentHashMismatch
		}
		if _, duplicate := stored[target.connectorID]; duplicate {
			return ErrContentHashMismatch
		}
		stored[target.connectorID] = target
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(stored) == 0 || len(stored) != len(summary.Targets) {
		return ErrContentHashMismatch
	}
	if summary.AccountID != ack.AccountID || summary.TunnelID != ack.TunnelID || summary.OperationID != ack.OperationID || summary.TargetSetHash != ack.TargetSetHash {
		return ErrIdentityMismatch
	}
	seen := make(map[string]struct{}, len(summary.Targets))
	failed := false
	allRevoked := true
	for _, item := range summary.Targets {
		if err := item.Target.Validate(); err != nil {
			return ErrInvalidInput
		}
		if _, duplicate := seen[item.Target.ConnectorID]; duplicate {
			return ErrContentHashMismatch
		}
		seen[item.Target.ConnectorID] = struct{}{}
		row, ok := stored[item.Target.ConnectorID]
		if !ok {
			return ErrContentHashMismatch
		}
		target, err := row.target()
		if err != nil {
			return err
		}
		if target != item.Target || row.hostID != item.Target.HostID {
			return ErrIdentityMismatch
		}
		expectedState := RotationTargetState(row.state)
		if item.Target.ConnectorID == ack.ConnectorID {
			switch ack.Status {
			case RotationAckRejected, RotationAckFailed:
				expectedState = RotationTargetFailed
			case RotationAckRevoked:
				expectedState = RotationTargetRevoked
			default:
				return ErrInvalidInput
			}
		}
		if !validRotationTargetState(expectedState) || item.State != expectedState {
			return ErrStaleProcess
		}
		if expectedState == RotationTargetFailed {
			expectedCode := Code(rotationString(row.failureCode))
			if item.Target.ConnectorID == ack.ConnectorID && (ack.Status == RotationAckRejected || ack.Status == RotationAckFailed) {
				expectedCode = ack.Code
			}
			if expectedCode == "" || item.Code != expectedCode {
				return ErrIdentityMismatch
			}
			failed = true
		} else if item.Code != "" {
			return ErrInvalidInput
		}
		if expectedState != RotationTargetRevoked {
			allRevoked = false
		}
	}
	if len(seen) != len(stored) {
		return ErrContentHashMismatch
	}
	wantStatus := RotationAggregatePending
	if failed {
		wantStatus = RotationAggregateFailed
	} else if allRevoked {
		wantStatus = RotationAggregateSucceeded
	}
	if summary.Status != wantStatus {
		return ErrStaleProcess
	}
	if (wantStatus == RotationAggregateSucceeded) != !summary.CompletedAt.IsZero() {
		return ErrInvalidInput
	}
	return nil
}

func rotationResultAckMatchesTarget(row sqlRotationTarget, ack CredentialRotationAck) bool {
	var sessionID string
	var processGeneration uint64
	switch RotationTargetState(row.state) {
	case RotationTargetChallenged, RotationTargetInstalled:
		sessionID, processGeneration = rotationString(row.proofSessionID), rotationUint(row.proofProcessGeneration)
	case RotationTargetReady:
		sessionID, processGeneration = rotationString(row.replacementSessionID), rotationUint(row.replacementProcessGeneration)
	case RotationTargetRevoking:
		sessionID, processGeneration = rotationString(row.revokeSessionID), rotationUint(row.revokeProcessGeneration)
	default:
		return false
	}
	return sessionID != "" && processGeneration > 0 && ack.SessionID == sessionID && ack.ProcessGeneration == processGeneration
}

func rotationFailureMessage(code Code) string {
	switch code {
	case CodeCapabilityMissing:
		return "connector does not support credential rotation"
	case CodeCredentialExpired:
		return "credential rotation credential expired"
	case CodeCredentialRotationNotReady:
		return "replacement connector was not ready"
	case CodeSnapshotRequired, CodeGenerationGap:
		return "connector requires a fresh configuration snapshot"
	case CodeStaleGeneration, CodeStaleSession:
		return "connector session generation is stale"
	default:
		return "credential rotation failed"
	}
}

func rotationResumeTarget(target sqlRotationTarget) (RotationResumeTarget, error) {
	item, err := target.target()
	if err != nil {
		return RotationResumeTarget{}, err
	}
	result := RotationResumeTarget{
		Target: item, State: RotationTargetState(target.state), Code: Code(rotationString(target.failureCode)),
		OverlapUntil: rotationTime(target.overlapUntil), NewCredentialValidUntil: rotationTime(target.newCredentialValidUntil),
	}
	if target.proofSessionID.Valid {
		result.Challenge, err = target.challenge()
		if err != nil {
			return RotationResumeTarget{}, err
		}
	}
	publicKey := base64.RawURLEncoding.EncodeToString(target.newPublicKey)
	if target.state == string(RotationTargetInstalled) || target.state == string(RotationTargetReady) || target.state == string(RotationTargetRevoking) || target.state == string(RotationTargetRevoked) {
		result.Install = CredentialRotationInstall{
			AccountID: target.accountID, TunnelID: target.tunnelID, OperationID: target.operationID,
			ConnectorID: target.connectorID, HostID: target.hostID, SessionID: rotationString(target.proofSessionID),
			ProcessGeneration: rotationUint(target.proofProcessGeneration), TargetSetHash: target.targetSetHash,
			OldCredentialGeneration: item.OldCredentialGeneration, NewCredentialGeneration: item.NewCredentialGeneration,
			NewIdentityKeyID: rotationString(target.newIdentityKeyID), NewIdentityKeyThumbprint: rotationString(target.newIdentityKeyThumbprint),
			NewPublicKey: publicKey, NewCredentialReference: rotationString(target.newCredentialReference),
			ChallengeNonce: rotationString(target.challengeNonce), OverlapUntil: rotationTime(target.overlapUntil),
			NewCredentialValidUntil: rotationTime(target.newCredentialValidUntil), ReplacementProcessGeneration: rotationUint(target.proofProcessGeneration) + 1,
		}
	}
	if target.state == string(RotationTargetReady) || target.state == string(RotationTargetRevoking) || target.state == string(RotationTargetRevoked) {
		result.Ready = CredentialRotationReady{
			AccountID: target.accountID, TunnelID: target.tunnelID, OperationID: target.operationID,
			ConnectorID: target.connectorID, HostID: target.hostID, SessionID: rotationString(target.replacementSessionID),
			PreviousSessionID: rotationString(target.proofSessionID), ProcessGeneration: rotationUint(target.replacementProcessGeneration),
			TargetSetHash: target.targetSetHash, OldCredentialGeneration: item.OldCredentialGeneration,
			NewCredentialGeneration: item.NewCredentialGeneration, NewIdentityKeyID: rotationString(target.newIdentityKeyID),
			NewIdentityKeyThumbprint: rotationString(target.newIdentityKeyThumbprint), NewPublicKey: publicKey,
			NewCredentialReference: rotationString(target.newCredentialReference), NewCredentialValidUntil: rotationTime(target.newCredentialValidUntil),
			ConfigGeneration: rotationUint(target.configGeneration), ConfigContentHash: "sha256:" + hex.EncodeToString(target.configContentHash),
			EdgeReady: rotationBool(target.edgeReady), RouteReady: rotationBool(target.routeReady), OriginReady: rotationBool(target.originReady), ReadyAt: rotationTime(target.readyAt),
		}
	}
	if target.state == string(RotationTargetRevoking) || target.state == string(RotationTargetRevoked) {
		result.Revoke = CredentialRotationRevoke{
			AccountID: target.accountID, TunnelID: target.tunnelID, OperationID: target.operationID,
			ConnectorID: target.connectorID, HostID: target.hostID, SessionID: rotationString(target.revokeSessionID),
			ProcessGeneration: rotationUint(target.revokeProcessGeneration), TargetSetHash: target.targetSetHash,
			OldCredentialGeneration: item.OldCredentialGeneration, NewCredentialGeneration: item.NewCredentialGeneration,
			RevokeNonce: rotationString(target.revokeNonce), IssuedAt: rotationTime(target.revokeIssuedAt), Deadline: rotationTime(target.revokeDeadline),
		}
	}
	return result, nil
}

func (s *SQLControlStore) LoadCredentialRotation(ctx context.Context, plan RotationPlan) (RotationResume, error) {
	if ctx == nil || s.valid() != nil || plan.Validate() != nil {
		return RotationResume{}, ErrInvalidInput
	}
	var result RotationResume
	err := s.DB.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		var accountID, resourceID, resourceKind, operationType, state string
		var completedAt sql.NullTime
		if err := tx.QueryRow(ctx, `
SELECT account_id, resource_id, resource_kind, operation_type, state, completed_at
FROM operations WHERE id = $1`, plan.OperationID).Scan(&accountID, &resourceID, &resourceKind, &operationType, &state, &completedAt); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrOperationNotFound
			}
			return err
		}
		if accountID != plan.AccountID || resourceID != plan.TunnelID || resourceKind != "tunnel" || operationType != "connector.credentials.rotate" || state == "cancelled" {
			return ErrIdentityMismatch
		}
		rows, err := tx.Query(ctx, strings.Replace(rotationTargetSelect, " AND connector_id = $4", "", 1)+` ORDER BY connector_id`, plan.OperationID, plan.AccountID, plan.TunnelID)
		if err != nil {
			return err
		}
		defer rows.Close()
		byConnector := make(map[string]RotationResumeTarget, len(plan.Targets))
		for rows.Next() {
			var target sqlRotationTarget
			if err := scanRotationTarget(rows, &target); err != nil {
				return err
			}
			if target.targetSetHash != plan.TargetSetHash || target.accountID != plan.AccountID || target.tunnelID != plan.TunnelID {
				return ErrContentHashMismatch
			}
			resumed, err := rotationResumeTarget(target)
			if err != nil {
				return err
			}
			byConnector[target.connectorID] = resumed
		}
		if err := rows.Err(); err != nil {
			return err
		}
		if len(byConnector) != len(plan.Targets) {
			return ErrContentHashMismatch
		}
		result = RotationResume{Plan: plan, Started: true, Targets: make([]RotationResumeTarget, 0, len(plan.Targets))}
		if completedAt.Valid {
			result.FinishedAt = completedAt.Time.UTC()
		}
		for _, item := range plan.Targets {
			resumed, ok := byConnector[item.ConnectorID]
			if !ok || resumed.Target != item {
				return ErrContentHashMismatch
			}
			result.Targets = append(result.Targets, resumed)
		}
		return nil
	})
	return result, err
}

// ListCredentialRotationPlans returns bounded, durable aggregate plans for a
// reconciler after restart. The target rows are the source of truth; this
// method never recaptures current connectors. Callers should pass each plan to
// PersistentServer.ResumeRotation and use their own bounded worker lease.
func (s *SQLControlStore) ListCredentialRotationPlans(ctx context.Context, limit int) ([]RotationPlan, error) {
	if ctx == nil || s.valid() != nil || limit < 1 || limit > 64 {
		return nil, ErrInvalidInput
	}
	plans := make([]RotationPlan, 0, limit)
	err := s.DB.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		rows, err := tx.Query(ctx, `
SELECT o.id, o.account_id, o.resource_id
FROM operations AS o
JOIN tunnel_connector_rotation_targets AS rt ON rt.operation_id = o.id
WHERE o.operation_type = 'connector.credentials.rotate'
  AND o.resource_kind = 'tunnel'
  AND o.state IN ('pending','running','uncertain')
GROUP BY o.id, o.account_id, o.resource_id, o.created_at
ORDER BY o.created_at, o.id
LIMIT $1`, limit)
		if err != nil {
			return err
		}
		type operationRef struct {
			operationID, accountID, tunnelID string
		}
		operations := make([]operationRef, 0, limit)
		for rows.Next() {
			var operation operationRef
			if err := rows.Scan(&operation.operationID, &operation.accountID, &operation.tunnelID); err != nil {
				rows.Close()
				return err
			}
			operations = append(operations, operation)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
		for _, operation := range operations {
			targetRows, err := tx.Query(ctx, strings.Replace(rotationTargetSelect, " AND connector_id = $4", "", 1)+` ORDER BY connector_id`, operation.operationID, operation.accountID, operation.tunnelID)
			if err != nil {
				return err
			}
			targets := make([]RotationTarget, 0, MaxRotationTargets)
			var targetSetHash string
			for targetRows.Next() {
				var row sqlRotationTarget
				if err := scanRotationTarget(targetRows, &row); err != nil {
					targetRows.Close()
					return err
				}
				item, err := row.target()
				if err != nil {
					targetRows.Close()
					return err
				}
				if targetSetHash == "" {
					targetSetHash = row.targetSetHash
				}
				if row.targetSetHash != targetSetHash || row.accountID != operation.accountID || row.tunnelID != operation.tunnelID {
					targetRows.Close()
					return ErrContentHashMismatch
				}
				targets = append(targets, item)
			}
			if err := targetRows.Err(); err != nil {
				targetRows.Close()
				return err
			}
			targetRows.Close()
			plan, err := NewRotationPlan(operation.accountID, operation.tunnelID, operation.operationID, targets)
			if err != nil || plan.TargetSetHash != targetSetHash {
				if err == nil {
					err = ErrContentHashMismatch
				}
				return err
			}
			plans = append(plans, plan)
		}
		return rows.Err()
	})
	return plans, err
}

// LoadCredentialRotationPlan resolves one operation without depending on the
// reconciler page. Inbound frames and terminal retries must remain routable
// even when more than one page of rotations is active or the operation has
// already reached a terminal state.
func (s *SQLControlStore) LoadCredentialRotationPlan(ctx context.Context, operationID string) (RotationPlan, error) {
	if ctx == nil || s.valid() != nil || ValidateIdentifier(operationID) != nil {
		return RotationPlan{}, ErrInvalidInput
	}
	var plan RotationPlan
	err := s.DB.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		var accountID, tunnelID, resourceKind, operationType string
		if err := tx.QueryRow(ctx, `
SELECT account_id, resource_id, resource_kind, operation_type
FROM operations WHERE id = $1`, operationID).Scan(&accountID, &tunnelID, &resourceKind, &operationType); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrOperationNotFound
			}
			return err
		}
		if resourceKind != "tunnel" || operationType != "connector.credentials.rotate" {
			return ErrIdentityMismatch
		}
		rows, err := tx.Query(ctx, strings.Replace(rotationTargetSelect, " AND connector_id = $4", "", 1)+` ORDER BY connector_id`, operationID, accountID, tunnelID)
		if err != nil {
			return err
		}
		defer rows.Close()
		targets := make([]RotationTarget, 0, MaxRotationTargets)
		var targetSetHash string
		for rows.Next() {
			var row sqlRotationTarget
			if err := scanRotationTarget(rows, &row); err != nil {
				return err
			}
			target, err := row.target()
			if err != nil {
				return err
			}
			if targetSetHash == "" {
				targetSetHash = row.targetSetHash
			}
			if row.accountID != accountID || row.tunnelID != tunnelID || row.targetSetHash != targetSetHash {
				return ErrContentHashMismatch
			}
			targets = append(targets, target)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		if len(targets) == 0 {
			return ErrOperationNotFound
		}
		loaded, err := NewRotationPlan(accountID, tunnelID, operationID, targets)
		if err != nil {
			return err
		}
		if loaded.TargetSetHash != targetSetHash {
			return ErrContentHashMismatch
		}
		plan = loaded
		return nil
	})
	return plan, err
}

// Ensure compile-time ownership of the persistence boundaries. The concrete
// SQL adapter is intentionally the only implementation in production code.
var _ PersistentControlStore = (*SQLControlStore)(nil)
var _ PersistentDrainStore = (*SQLControlStore)(nil)
var _ IdentityProofVerifier = (*SQLControlStore)(nil)
var _ RotationPersistence = (*SQLControlStore)(nil)
var _ RotationRecoveryStore = (*SQLControlStore)(nil)
var _ RotationSessionAuthorizer = (*SQLControlStore)(nil)
