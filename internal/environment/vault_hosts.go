package environment

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
)

const MaximumVaultProjectionBytes = (256 << 10) + (64 << 10)
const VaultProjectionBundleSchema = "paperboat.environment-projection-bundle/v1"
const VaultProjectionObservationSchema = "paperboat.environment-projection-observation/v1"

type VaultHostSelection struct {
	OwnerKind string `json:"owner_kind"`
	OwnerID   string `json:"owner_id"`
	Name      string `json:"name"`
}
type VaultHostKeyRequest struct {
	OperationID            string `json:"operation_id"`
	InstallationGeneration uint64 `json:"installation_generation"`
	HostKeyGeneration      uint64 `json:"host_key_generation"`
	HostPublic             string `json:"host_public"`
}
type VaultHostProvision struct {
	OperationID                 string               `json:"operation_id"`
	ExpectedSelectionGeneration uint64               `json:"expected_selection_generation"`
	Selection                   []VaultHostSelection `json:"selection"`
	Envelope                    string               `json:"envelope"`
}
type VaultProjectionBundle struct {
	Schema                 string `json:"schema"`
	AccountID              string `json:"account_id"`
	MachineID              string `json:"machine_id"`
	InstallationGeneration uint64 `json:"installation_generation"`
	HostKeyGeneration      uint64 `json:"host_key_generation"`
	HostPublic             string `json:"host_public"`
	WriterPublic           string `json:"writer_public"`
	FenceGeneration        uint64 `json:"fence_generation"`
	SelectionGeneration    uint64 `json:"selection_generation"`
	ProjectionRevision     uint64 `json:"projection_revision"`
	DocumentID             string `json:"document_id"`
	Envelope               string `json:"envelope"`
	State                  string `json:"state"`
}
type VaultHostState struct {
	Bundle    VaultProjectionBundle `json:"bundle"`
	Selection []VaultHostSelection  `json:"selection"`
}
type VaultProjectionCursor struct {
	Revision   uint64 `json:"revision"`
	DocumentID string `json:"document_id"`
}
type VaultProjectionObservation struct {
	Schema             string                 `json:"schema"`
	ObservationSeq     uint64                 `json:"observation_seq"`
	HostRecipientKeyID string                 `json:"host_recipient_key_id"`
	Projection         *VaultProjectionCursor `json:"projection"`
	FenceGeneration    uint64                 `json:"fence_generation"`
	State              string                 `json:"state"`
	ErrorCode          *string                `json:"error_code"`
	ObservedAt         time.Time              `json:"observed_at"`
}
type vaultProjectionSource struct {
	_         struct{} `cbor:",toarray"`
	OwnerKind string
	OwnerID   string
	MachineID string
	Epoch     uint64
	Revision  uint64
	Digest    []byte
}
type vaultProjectionClaims struct {
	_                      struct{} `cbor:",toarray"`
	Domain                 string
	Version                uint64
	Issuer                 string
	OwnerAccount           string
	MachineID              string
	InstallationGeneration uint64
	HostKeyGeneration      uint64
	HostPublic             []byte
	SelectionGeneration    uint64
	Revision               uint64
	Previous               []byte
	Sources                []vaultProjectionSource
	WriterVaultGeneration  uint64
	WriterPublic           []byte
}
type vaultProjectionEnvelope struct {
	_          struct{} `cbor:",toarray"`
	Claims     []byte
	Enc        []byte
	Ciphertext []byte
	Signature  []byte
}

func parseVaultProjection(raw []byte, issuer string, writer PasswordVaultMetadata) (vaultProjectionClaims, error) {
	var env vaultProjectionEnvelope
	var c vaultProjectionClaims
	if !decodeVaultCanonical(raw, MaximumVaultProjectionBytes, &env) || !decodeVaultCanonical(env.Claims, 64<<10, &c) || c.Domain != "paperboat.environment.host-projection" || c.Version != 1 || c.Issuer != issuer || c.OwnerAccount != writer.Head.AccountID || c.WriterVaultGeneration != writer.Head.Generation || !bytes.Equal(c.WriterPublic, writer.WriterPublicKey[:]) || !validIdentifier(c.MachineID) || !validCounter(c.InstallationGeneration) || !validCounter(c.HostKeyGeneration) || !validX25519Public(c.HostPublic) || !validCounter(c.SelectionGeneration) || !validCounter(c.Revision) || len(c.Previous) != 32 || (c.Revision == 1) != allZeroBytes(c.Previous) || c.Sources == nil || len(c.Sources) > 130 || len(env.Enc) != 32 || len(env.Ciphertext) <= 16 || len(env.Ciphertext) > (256<<10)+16 || len(env.Signature) != 64 {
		return c, ErrProtocolInvalid
	}
	previous := ""
	for _, source := range c.Sources {
		coordinate := source.OwnerKind + "\x00" + source.OwnerID + "\x00" + source.MachineID
		if (source.OwnerKind != "personal" && source.OwnerKind != "team") || !validIdentifier(source.OwnerID) || (source.MachineID != "" && !validIdentifier(source.MachineID)) || (source.OwnerKind == "team" && source.MachineID != "") || !validCounter(source.Epoch) || !validCounter(source.Revision) || len(source.Digest) != 32 || coordinate <= previous {
			return c, ErrProtocolInvalid
		}
		previous = coordinate
	}
	message, _ := canonicalEncoding.Marshal([]any{"paperboat.environment.host-projection-signature", uint64(1), env.Claims, env.Enc, env.Ciphertext})
	if !ed25519.Verify(writer.WriterPublicKey[:], message, env.Signature) {
		return c, ErrProtocolSignature
	}
	return c, nil
}
func (o VaultProjectionObservation) Valid() bool {
	if o.Schema != VaultProjectionObservationSchema || !validCounter(o.ObservationSeq) || !stringsVaultKeyID(o.HostRecipientKeyID) || o.FenceGeneration > MaxBrowserInteger || o.ObservedAt.IsZero() || !slices.Contains([]string{"pending", "applied", "failed", "revoked"}, o.State) || (o.State == "failed") != (o.ErrorCode != nil) || (o.ErrorCode != nil && !safeErrorCode.MatchString(*o.ErrorCode)) {
		return false
	}
	return o.Projection == nil || (validCounter(o.Projection.Revision) && digestExpression.MatchString(o.Projection.DocumentID))
}
func stringsVaultKeyID(id string) bool {
	if len(id) != 48 || id[:5] != "envk_" {
		return false
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(id[5:])
	return err == nil && len(raw) == 32
}
func vaultHostKeyID(public []byte) string {
	sum := sha256.Sum256([]byte(`{"crv":"X25519","kty":"OKP","x":"` + base64.RawURLEncoding.EncodeToString(public) + `"}`))
	return "envk_" + base64.RawURLEncoding.EncodeToString(sum[:])
}
func authorizeVaultHostTx(ctx context.Context, tx *db.Tx, account, machine string) (uint64, error) {
	var generation uint64
	var mode string
	var roles []string
	err := tx.QueryRow(ctx, `SELECT installation_generation,setup_mode,setup_roles FROM user_machines WHERE id=$1 AND user_id=$2 AND deleted_at IS NULL AND revoked_at IS NULL AND state NOT IN('revoked','deleted')`, machine, account).Scan(&generation, &mode, &roles)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrMachineNotFound
	}
	if err != nil {
		return 0, err
	}
	if mode != "host" && !slices.Contains(roles, "host") {
		return 0, ErrMachineNotHost
	}
	return generation, nil
}
func readVaultHostTx(ctx context.Context, tx *db.Tx, account, machine string) (VaultHostState, error) {
	var out VaultHostState
	var public, writer, envelope, selection []byte
	var applied uint64
	b := &out.Bundle
	b.Schema = VaultProjectionBundleSchema
	b.AccountID = account
	b.MachineID = machine
	err := tx.QueryRow(ctx, `SELECT h.installation_generation,h.host_key_generation,h.host_public,h.writer_public,h.selection_generation,h.selection,h.projection_revision,h.document_id,h.envelope,h.applied_fence_generation,COALESCE(f.generation,0) FROM environment_vault_hosts h LEFT JOIN environment_vault_projection_fences f USING(machine_id) WHERE h.machine_id=$1 AND h.account_id=$2`, machine, account).Scan(&b.InstallationGeneration, &b.HostKeyGeneration, &public, &writer, &b.SelectionGeneration, &selection, &b.ProjectionRevision, &b.DocumentID, &envelope, &applied, &b.FenceGeneration)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, ErrNotFound
	}
	if err != nil {
		return out, err
	}
	if json.Unmarshal(selection, &out.Selection) != nil || out.Selection == nil {
		return out, ErrProtocolInvalid
	}
	b.HostPublic = b64VaultPublic(public)
	b.WriterPublic = b64VaultPublic(writer)
	b.State = "pending"
	if b.ProjectionRevision > 0 && len(envelope) > 0 && applied == b.FenceGeneration {
		b.State = "ready"
		b.Envelope = b64VaultPublic(envelope)
	}
	return out, nil
}
func b64VaultPublic(raw []byte) string { return base64.RawURLEncoding.EncodeToString(raw) }
func (s *Service) RegisterVaultHostKey(ctx context.Context, account, machine string, request VaultHostKeyRequest) (VaultProjectionBundle, error) {
	var out VaultProjectionBundle
	public, err := DecodeCanonicalBase64URL(request.HostPublic, 32)
	if err != nil || !validX25519Public(public) || !validCounter(request.InstallationGeneration) || !validCounter(request.HostKeyGeneration) {
		return out, ErrProtocolInvalid
	}
	err = s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		if err := lockVaultScopes(ctx, tx); err != nil {
			return err
		}
		generation, err := authorizeVaultHostTx(ctx, tx, account, machine)
		if err != nil {
			return err
		}
		if generation != request.InstallationGeneration {
			return ErrVersionConflict
		}
		// Registration retries return the current binding, including explicit reprovision.
		if !validIdentifier(request.OperationID) {
			return ErrProtocolInvalid
		}
		existing, err := readVaultHostTx(ctx, tx, account, machine)
		exists := err == nil
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		if exists && existing.Bundle.InstallationGeneration == generation && existing.Bundle.HostKeyGeneration == request.HostKeyGeneration && existing.Bundle.HostPublic == request.HostPublic {
			out = existing.Bundle
			return nil
		}
		if exists && existing.Bundle.InstallationGeneration == generation && request.HostKeyGeneration != existing.Bundle.HostKeyGeneration+1 {
			return ErrVersionConflict
		}
		writer, err := s.vaultMetadataTx(ctx, tx, account)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO environment_vault_projection_fences(machine_id,generation) VALUES($1,1) ON CONFLICT(machine_id) DO UPDATE SET generation=environment_vault_projection_fences.generation+1`, machine); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO environment_vault_hosts(machine_id,account_id,installation_generation,host_key_generation,host_public,writer_public) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(machine_id) DO UPDATE SET installation_generation=EXCLUDED.installation_generation,host_key_generation=EXCLUDED.host_key_generation,host_public=EXCLUDED.host_public,envelope='',applied_fence_generation=0,observation_seq=0,observation_digest=NULL,observation=NULL`, machine, account, generation, request.HostKeyGeneration, public, writer.WriterPublicKey[:]); err != nil {
			return err
		}
		state, err := readVaultHostTx(ctx, tx, account, machine)
		out = state.Bundle
		return err
	})
	return out, err
}
func (s *Service) GetVaultHost(ctx context.Context, account, machine string) (VaultHostState, error) {
	var out VaultHostState
	err := s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		if err := lockVaultScopes(ctx, tx); err != nil {
			return err
		}
		if _, err := authorizeVaultHostTx(ctx, tx, account, machine); err != nil {
			return err
		}
		var err error
		out, err = readVaultHostTx(ctx, tx, account, machine)
		return err
	})
	return out, err
}
func (s *Service) ProvisionVaultHost(ctx context.Context, account, machine string, request VaultHostProvision) (VaultProjectionBundle, error) {
	var out VaultProjectionBundle
	if request.Selection == nil || len(request.Selection) > 128 {
		return out, ErrProtocolInvalid
	}
	raw, err := DecodeCanonicalBase64URL(request.Envelope, MaximumVaultProjectionBytes)
	if err != nil {
		return out, err
	}
	err = s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		if err := lockVaultScopes(ctx, tx); err != nil {
			return err
		}
		if err := allowVaultWritesTx(ctx, tx, account); err != nil {
			return err
		}
		generation, err := authorizeVaultHostTx(ctx, tx, account, machine)
		if err != nil {
			return err
		}
		replay, digest, err := vaultOperationTx(ctx, tx, account, request.OperationID, "host-provision:"+machine, request, &out)
		if err != nil || replay {
			return err
		}
		// Authorize every requested source before accessing recipient key material.
		scopes := map[string]VaultScopeState{}
		names := map[string]bool{}
		for _, selection := range request.Selection {
			if !portableName.MatchString(selection.Name) || len(selection.Name) > 128 || names[selection.Name] {
				return ErrInvalidName
			}
			names[selection.Name] = true
			if selection.OwnerKind == "team" {
				if err := allowVaultTeamWritesTx(ctx, tx, selection.OwnerID); err != nil {
					return err
				}
			}
			if _, err := authorizeVaultScopeTx(ctx, tx, account, selection.OwnerKind, selection.OwnerID, ""); err != nil {
				return err
			}
			scope, err := readVaultScopeTx(ctx, tx, selection.OwnerKind, selection.OwnerID, "")
			if err != nil {
				return err
			}
			scopes[selection.OwnerKind+"\x00"+selection.OwnerID+"\x00"] = scope
		}
		override, err := readVaultScopeTx(ctx, tx, "personal", account, machine)
		if err == nil {
			scopes["personal\x00"+account+"\x00"+machine] = override
		} else if !errors.Is(err, ErrNotFound) {
			return err
		}
		host, err := readVaultHostTx(ctx, tx, account, machine)
		if err != nil {
			return err
		}
		if host.Bundle.InstallationGeneration != generation || host.Bundle.SelectionGeneration != request.ExpectedSelectionGeneration {
			return ErrVersionConflict
		}
		writer, err := s.vaultMetadataTx(ctx, tx, account)
		if err != nil {
			return err
		}
		claims, err := parseVaultProjection(raw, s.passwordVaultIssuer, writer)
		if err != nil {
			return err
		}
		if claims.MachineID != machine || claims.InstallationGeneration != generation || claims.HostKeyGeneration != host.Bundle.HostKeyGeneration || b64VaultPublic(claims.HostPublic) != host.Bundle.HostPublic || claims.SelectionGeneration != host.Bundle.SelectionGeneration+1 || claims.Revision != host.Bundle.ProjectionRevision+1 || (host.Bundle.ProjectionRevision > 0 && digestText(claims.Previous) != host.Bundle.DocumentID) || len(claims.Sources) != len(scopes) {
			return ErrVersionConflict
		}
		for _, source := range claims.Sources {
			scope, ok := scopes[source.OwnerKind+"\x00"+source.OwnerID+"\x00"+source.MachineID]
			if !ok || scope.KeyEpoch != source.Epoch || scope.Revision != source.Revision || scope.DocumentID != digestText(source.Digest) {
				return ErrVersionConflict
			}
		}
		selection, err := json.Marshal(request.Selection)
		if err != nil || len(selection) > 65536 {
			return ErrLimitExceeded
		}
		documentDigest := sha256.Sum256(raw)
		if _, err := tx.Exec(ctx, `UPDATE environment_vault_hosts SET selection_generation=$2,selection=$3,projection_revision=$4,document_id=$5,envelope=$6,writer_public=$7,applied_fence_generation=$8 WHERE machine_id=$1`, machine, claims.SelectionGeneration, selection, claims.Revision, digestText(documentDigest[:]), raw, writer.WriterPublicKey[:], host.Bundle.FenceGeneration); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM environment_vault_projection_sources WHERE machine_id=$1`, machine); err != nil {
			return err
		}
		// Always watch the implicit override coordinate, even before its first write.
		scopes["personal\x00"+account+"\x00"+machine] = VaultScopeState{OwnerKind: "personal", OwnerID: account, MachineID: machine}
		coordinates := make([]string, 0, len(scopes))
		for coordinate := range scopes {
			coordinates = append(coordinates, coordinate)
		}
		sort.Strings(coordinates)
		for _, coordinate := range coordinates {
			scope := scopes[coordinate]
			if _, err := tx.Exec(ctx, `INSERT INTO environment_vault_projection_sources(machine_id,owner_kind,owner_id,source_machine_id) VALUES($1,$2,$3,$4)`, machine, scope.OwnerKind, scope.OwnerID, scope.MachineID); err != nil {
				return err
			}
		}
		state, err := readVaultHostTx(ctx, tx, account, machine)
		if err != nil {
			return err
		}
		out = state.Bundle
		return saveVaultOperationTx(ctx, tx, account, request.OperationID, digest, out)
	})
	return out, err
}
func (s *Service) RecordVaultProjectionObservation(ctx context.Context, environmentID, machine string, observation *VaultProjectionObservation) (*VaultProjectionBundle, error) {
	if observation == nil || !observation.Valid() {
		return nil, ErrObservationInvalid
	}
	var out VaultProjectionBundle
	err := s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		if err := lockVaultScopes(ctx, tx); err != nil {
			return err
		}
		var account string
		if err := tx.QueryRow(ctx, `SELECT user_id FROM user_machines WHERE id=$1 AND environment_id=$2`, machine, environmentID).Scan(&account); errors.Is(err, pgx.ErrNoRows) {
			return ErrMachineNotFound
		} else if err != nil {
			return err
		}
		generation, err := authorizeVaultHostTx(ctx, tx, account, machine)
		if err != nil {
			return err
		}
		host, err := readVaultHostTx(ctx, tx, account, machine)
		if err != nil {
			return err
		}
		public, err := DecodeCanonicalBase64URL(host.Bundle.HostPublic, 32)
		if err != nil {
			return err
		}
		if generation != host.Bundle.InstallationGeneration || vaultHostKeyID(public) != observation.HostRecipientKeyID {
			return ErrObservationInvalid
		}
		raw, err := json.Marshal(observation)
		if err != nil || len(raw) > 4096 {
			return ErrObservationInvalid
		}
		sum := sha256.Sum256(raw)
		var sequence uint64
		var previous []byte
		if err := tx.QueryRow(ctx, `SELECT observation_seq,observation_digest FROM environment_vault_hosts WHERE machine_id=$1`, machine).Scan(&sequence, &previous); err != nil {
			return err
		}
		if observation.ObservationSeq < sequence || (observation.ObservationSeq == sequence && !bytes.Equal(previous, sum[:])) || observation.FenceGeneration > host.Bundle.FenceGeneration {
			return ErrObservationInvalid
		}
		if observation.Projection != nil && (observation.Projection.Revision > host.Bundle.ProjectionRevision || (observation.Projection.Revision == host.Bundle.ProjectionRevision && observation.Projection.DocumentID != host.Bundle.DocumentID)) {
			return ErrObservationInvalid
		}
		if observation.State == "applied" && observation.Projection == nil {
			return ErrObservationInvalid
		}
		if _, err := tx.Exec(ctx, `UPDATE environment_vault_hosts SET observation_seq=$2,observation_digest=$3,observation=$4 WHERE machine_id=$1`, machine, observation.ObservationSeq, sum[:], raw); err != nil {
			return err
		}
		out = host.Bundle
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}
