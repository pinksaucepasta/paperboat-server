// Package releaseauthority records decisions made by the independent TUF
// release authority. It verifies a threshold-signed bundle but never has a
// private key and never modifies release metadata itself.
package releaseauthority

import (
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

	"github.com/pinksaucepasta/paperboat-server/internal/audit"
	"github.com/pinksaucepasta/paperboat-server/internal/canonicaljson"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
)

const SchemaV1 = "paperboat.release-authority-bundle/v1"

var (
	ErrInvalid   = errors.New("release authority bundle is invalid")
	ErrSignature = errors.New("release authority bundle signature is invalid")
	ErrConflict  = errors.New("release authority import conflicts with an earlier operation")
)

type Key struct {
	ID     string
	Public ed25519.PublicKey
}
type Config struct {
	Keys      []Key
	Threshold int
	Now       func() time.Time
}
type Signature struct {
	KeyID     string `json:"key_id"`
	Signature string `json:"signature"`
}
type Bundle struct {
	Schema             string      `json:"schema"`
	ReleaseID          string      `json:"release_id"`
	Version            string      `json:"version"`
	Platform           string      `json:"platform"`
	Architecture       string      `json:"architecture"`
	Action             string      `json:"action"`
	PolicyRevision     uint64      `json:"policy_revision"`
	RolloutPercentage  uint8       `json:"rollout_percentage"`
	TUFIndexTarget     string      `json:"tuf_index_target"`
	TUFIndexSHA256     string      `json:"tuf_index_sha256"`
	AuthorityRequestID string      `json:"authority_request_id"`
	IssuedAt           time.Time   `json:"issued_at"`
	ExpiresAt          time.Time   `json:"expires_at"`
	Signatures         []Signature `json:"signatures"`
}
type Request struct {
	ID                string     `json:"id"`
	Action            string     `json:"action"`
	ReleaseID         string     `json:"release_id"`
	Version           string     `json:"version"`
	Platform          string     `json:"platform"`
	Architecture      string     `json:"architecture"`
	PolicyRevision    uint64     `json:"policy_revision"`
	RolloutPercentage uint8      `json:"rollout_percentage"`
	Status            string     `json:"status"`
	CreatedAt         time.Time  `json:"created_at"`
	FulfilledAt       *time.Time `json:"fulfilled_at,omitempty"`
}
type Record struct {
	ID string `json:"id"`
	Bundle
	ImportedAt time.Time `json:"imported_at"`
}
type Service struct {
	db        *db.DB
	audit     *audit.Writer
	keys      map[string]ed25519.PublicKey
	threshold int
	now       func() time.Time
}

func ParseKeys(values []string) ([]Key, error) {
	keys := make([]Key, 0, len(values))
	seen := map[string]bool{}
	for _, value := range values {
		id, encoded, ok := strings.Cut(strings.TrimSpace(value), ":")
		raw, err := base64.RawURLEncoding.DecodeString(encoded)
		if !ok || id == "" || len(id) > 64 || seen[id] || err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, ErrInvalid
		}
		seen[id] = true
		keys = append(keys, Key{ID: id, Public: ed25519.PublicKey(raw)})
	}
	return keys, nil
}
func New(store *db.DB, writer *audit.Writer, config Config) (*Service, error) {
	if store == nil || config.Threshold < 2 || config.Threshold > len(config.Keys) || len(config.Keys) > 16 {
		return nil, ErrInvalid
	}
	keys := make(map[string]ed25519.PublicKey, len(config.Keys))
	for _, key := range config.Keys {
		if key.ID == "" || len(key.Public) != ed25519.PublicKeySize || keys[key.ID] != nil {
			return nil, ErrInvalid
		}
		keys[key.ID] = append(ed25519.PublicKey(nil), key.Public...)
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &Service{db: store, audit: writer, keys: keys, threshold: config.Threshold, now: config.Now}, nil
}
func Decode(raw []byte) (Bundle, error) {
	if len(raw) == 0 || len(raw) > 64<<10 || canonicaljson.RejectDuplicateFields(raw) != nil {
		return Bundle{}, ErrInvalid
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	var value Bundle
	var extra any
	if decoder.Decode(&value) != nil || decoder.Decode(&extra) == nil {
		return Bundle{}, ErrInvalid
	}
	return value, nil
}
func (s *Service) Verify(bundle Bundle) error {
	if bundle.Schema != SchemaV1 || !validValue(bundle.ReleaseID, 128) || !validVersion(bundle.Version) || (bundle.Platform != "darwin" && bundle.Platform != "linux" && bundle.Platform != "windows") || (bundle.Architecture != "amd64" && bundle.Architecture != "arm64") || !validAction(bundle.Action) || bundle.PolicyRevision == 0 || !validValue(bundle.TUFIndexTarget, 256) || !validValue(bundle.AuthorityRequestID, 128) || len(bundle.TUFIndexSHA256) != 64 || !lowerHex(bundle.TUFIndexSHA256) || bundle.IssuedAt.IsZero() || bundle.ExpiresAt.IsZero() || !bundle.ExpiresAt.After(bundle.IssuedAt) || bundle.ExpiresAt.Sub(bundle.IssuedAt) > 30*24*time.Hour || !s.now().UTC().Before(bundle.ExpiresAt.UTC()) || bundle.IssuedAt.After(s.now().UTC().Add(5*time.Minute)) {
		return ErrInvalid
	}
	if bundle.Action == "promote" && bundle.RolloutPercentage == 0 || bundle.Action == "pause" && bundle.RolloutPercentage != 0 || (bundle.Action == "quarantine" || bundle.Action == "revoke") && bundle.RolloutPercentage != 0 {
		return ErrInvalid
	}
	payload, err := canonical(bundle)
	if err != nil {
		return ErrInvalid
	}
	seen := map[string]bool{}
	valid := 0
	for _, signature := range bundle.Signatures {
		key, ok := s.keys[signature.KeyID]
		decoded, decodeErr := base64.RawURLEncoding.DecodeString(signature.Signature)
		if !ok || seen[signature.KeyID] || decodeErr != nil || len(decoded) != ed25519.SignatureSize {
			return ErrSignature
		}
		seen[signature.KeyID] = true
		if ed25519.Verify(key, append([]byte("paperboat.release-authority.v1\x00"), payload...), decoded) {
			valid++
		} else {
			return ErrSignature
		}
	}
	if valid < s.threshold {
		return ErrSignature
	}
	return nil
}
func (s *Service) Import(ctx context.Context, actor, idempotency string, raw []byte) (Record, error) {
	if !validValue(actor, 128) || !validValue(idempotency, 128) || len(idempotency) < 8 {
		return Record{}, ErrInvalid
	}
	bundle, err := Decode(raw)
	if err != nil {
		return Record{}, err
	}
	if err = s.Verify(bundle); err != nil {
		return Record{}, err
	}
	requestHash := sha256.Sum256(raw)
	payload, _ := canonical(bundle)
	signatures, _ := json.Marshal(bundle.Signatures)
	bundleID := "rab_" + hex.EncodeToString(requestHash[:16])
	var result Record
	err = s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		op, operationErr := tx.Queries().GetReleaseAuthorityImportOperation(ctx, dbsqlc.GetReleaseAuthorityImportOperationParams{ActorUserID: actor, IdempotencyKey: idempotency})
		if operationErr == nil {
			if string(op.RequestHash) != string(requestHash[:]) {
				return ErrConflict
			}
			row, rowErr := tx.Queries().GetReleaseAuthorityBundle(ctx, op.BundleID)
			if rowErr != nil {
				return rowErr
			}
			result = mapRecord(row)
			return nil
		}
		if !errors.Is(operationErr, sql.ErrNoRows) {
			return operationErr
		}
		latest, latestErr := tx.Queries().GetLatestReleaseAuthorityBundleForUpdate(ctx, dbsqlc.GetLatestReleaseAuthorityBundleForUpdateParams{ReleaseID: bundle.ReleaseID, Platform: bundle.Platform, Architecture: bundle.Architecture})
		if latestErr == nil && bundle.PolicyRevision <= uint64(latest.PolicyRevision) {
			return ErrConflict
		}
		if latestErr != nil && !errors.Is(latestErr, sql.ErrNoRows) {
			return latestErr
		}
		request, requestErr := tx.Queries().GetReleaseAuthorityRequestForUpdate(ctx, bundle.AuthorityRequestID)
		if requestErr != nil || request.Status != "pending" || request.Action != bundle.Action || request.ReleaseID != bundle.ReleaseID || request.Version != bundle.Version || request.Platform != bundle.Platform || request.Architecture != bundle.Architecture || uint64(request.PolicyRevision) != bundle.PolicyRevision || uint8(request.RolloutPercentage) != bundle.RolloutPercentage {
			return ErrConflict
		}
		row, createErr := tx.Queries().CreateReleaseAuthorityBundle(ctx, dbsqlc.CreateReleaseAuthorityBundleParams{ID: bundleID, ReleaseID: bundle.ReleaseID, Version: bundle.Version, Platform: bundle.Platform, Architecture: bundle.Architecture, Action: bundle.Action, PolicyRevision: int64(bundle.PolicyRevision), Payload: payload, PayloadHash: requestHash[:], Signatures: signatures, IssuedAt: bundle.IssuedAt.UTC(), ExpiresAt: bundle.ExpiresAt.UTC(), AuthorityRequestID: bundle.AuthorityRequestID, ImportedByUserID: actor})
		if createErr != nil {
			return createErr
		}
		if err := tx.Queries().CreateReleaseAuthorityImportOperation(ctx, dbsqlc.CreateReleaseAuthorityImportOperationParams{ActorUserID: actor, IdempotencyKey: idempotency, RequestHash: requestHash[:], BundleID: row.ID}); err != nil {
			return err
		}
		if _, err := tx.Queries().FulfillReleaseAuthorityRequest(ctx, dbsqlc.FulfillReleaseAuthorityRequestParams{ID: request.ID, FulfilledBundleID: sql.NullString{String: row.ID, Valid: true}}); err != nil {
			return err
		}
		result = mapRecord(row)
		return s.audit.WriteTx(ctx, tx, audit.Event{ActorUserID: actor, ActorType: audit.ActorAdmin, EventType: "release_authority.bundle_imported", ResourceType: "release_authority_bundle", ResourceID: row.ID, IdempotencyKey: idempotency, Metadata: map[string]any{"action": bundle.Action, "release_id": bundle.ReleaseID, "platform": bundle.Platform, "architecture": bundle.Architecture, "policy_revision": bundle.PolicyRevision}})
	})
	return result, err
}
func (s *Service) Request(ctx context.Context, actor, idempotency string, request Request) (Request, error) {
	if !validValue(actor, 128) || !validValue(idempotency, 128) || len(idempotency) < 8 || !validAction(request.Action) || !validValue(request.ReleaseID, 128) || !validVersion(request.Version) || (request.Platform != "darwin" && request.Platform != "linux" && request.Platform != "windows") || (request.Architecture != "amd64" && request.Architecture != "arm64") || request.PolicyRevision == 0 || (request.Action == "promote" && request.RolloutPercentage == 0) || (request.Action != "promote" && request.RolloutPercentage != 0) {
		return Request{}, ErrInvalid
	}
	payload, _ := json.Marshal(struct {
		Action, ReleaseID, Version, Platform, Architecture string
		PolicyRevision                                     uint64
		RolloutPercentage                                  uint8
	}{request.Action, request.ReleaseID, request.Version, request.Platform, request.Architecture, request.PolicyRevision, request.RolloutPercentage})
	hash := sha256.Sum256(payload)
	request.ID = "rar_" + hex.EncodeToString(hash[:16])
	var result Request
	err := s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		existing, err := tx.Queries().GetReleaseAuthorityRequestForIdempotency(ctx, dbsqlc.GetReleaseAuthorityRequestForIdempotencyParams{RequestedByUserID: actor, IdempotencyKey: idempotency})
		if err == nil {
			if string(existing.RequestHash) != string(hash[:]) {
				return ErrConflict
			}
			result = mapRequest(existing)
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		row, err := tx.Queries().CreateReleaseAuthorityRequest(ctx, dbsqlc.CreateReleaseAuthorityRequestParams{ID: request.ID, Action: request.Action, ReleaseID: request.ReleaseID, Version: request.Version, Platform: request.Platform, Architecture: request.Architecture, PolicyRevision: int64(request.PolicyRevision), RolloutPercentage: int32(request.RolloutPercentage), RequestedByUserID: actor, IdempotencyKey: idempotency, RequestHash: hash[:]})
		if err != nil {
			return err
		}
		result = mapRequest(row)
		return s.audit.WriteTx(ctx, tx, audit.Event{ActorUserID: actor, ActorType: audit.ActorAdmin, EventType: "release_authority.requested", ResourceType: "release_authority_request", ResourceID: row.ID, IdempotencyKey: idempotency, Metadata: map[string]any{"action": request.Action, "release_id": request.ReleaseID, "policy_revision": request.PolicyRevision}})
	})
	return result, err
}
func (s *Service) ListRequests(ctx context.Context) ([]Request, error) {
	rows, err := s.db.Queries().ListReleaseAuthorityRequests(ctx, 100)
	if err != nil {
		return nil, err
	}
	result := make([]Request, 0, len(rows))
	for _, row := range rows {
		result = append(result, mapRequest(row))
	}
	return result, nil
}
func (s *Service) List(ctx context.Context) ([]Record, error) {
	rows, err := s.db.Queries().ListReleaseAuthorityBundles(ctx, 100)
	if err != nil {
		return nil, err
	}
	out := make([]Record, 0, len(rows))
	for _, row := range rows {
		out = append(out, mapRecord(row))
	}
	return out, nil
}
func canonical(bundle Bundle) ([]byte, error) { bundle.Signatures = nil; return json.Marshal(bundle) }
func mapRecord(row dbsqlc.ReleaseAuthorityBundle) Record {
	var bundle Bundle
	if json.Unmarshal(row.Payload, &bundle) != nil {
		return Record{}
	}
	var signatures []Signature
	if json.Unmarshal(row.Signatures, &signatures) != nil {
		return Record{}
	}
	bundle.Signatures = signatures
	return Record{ID: row.ID, Bundle: bundle, ImportedAt: row.ImportedAt.UTC()}
}
func mapRequest(row dbsqlc.ReleaseAuthorityRequest) Request {
	result := Request{ID: row.ID, Action: row.Action, ReleaseID: row.ReleaseID, Version: row.Version, Platform: row.Platform, Architecture: row.Architecture, PolicyRevision: uint64(row.PolicyRevision), RolloutPercentage: uint8(row.RolloutPercentage), Status: row.Status, CreatedAt: row.CreatedAt.UTC()}
	if row.FulfilledAt.Valid {
		at := row.FulfilledAt.Time.UTC()
		result.FulfilledAt = &at
	}
	return result
}
func validAction(value string) bool {
	return value == "promote" || value == "pause" || value == "quarantine" || value == "revoke"
}
func validValue(value string, max int) bool {
	value = strings.TrimSpace(value)
	return value != "" && len(value) <= max && !strings.ContainsAny(value, "\x00\r\n")
}
func lowerHex(value string) bool {
	_, err := hex.DecodeString(value)
	return err == nil && value == strings.ToLower(value)
}
func validVersion(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		for _, char := range part {
			if char < '0' || char > '9' {
				return false
			}
		}
	}
	return true
}
func (b Bundle) String() string {
	return fmt.Sprintf("%s:%s:%d", b.ReleaseID, b.Platform, b.PolicyRevision)
}
