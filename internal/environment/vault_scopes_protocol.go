package environment

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
)

const MaximumVaultScopeBytes = (256 << 10) + 2048
const MaximumTeamGrantBytes = 4096
const MaximumVaultTeamMembers = 128

type VaultScopeState struct {
	WriterPublic string `json:"writer_public"`
	OwnerKind    string `json:"owner_kind"`
	OwnerID      string `json:"owner_id"`
	MachineID    string `json:"machine_id"`
	KeyEpoch     uint64 `json:"key_epoch"`
	Revision     uint64 `json:"revision"`
	DocumentID   string `json:"document_id"`
	Envelope     string `json:"envelope"`
}
type VaultScopePut struct {
	OperationID string `json:"operation_id"`
	Envelope    string `json:"envelope"`
}
type VaultTeamCreate struct {
	ExpectedTeamGeneration uint64 `json:"expected_team_generation"`
	VaultEnvelope          string `json:"vault_envelope"`
	OperationID            string `json:"operation_id"`
	TeamID                 string `json:"team_id"`
	ScopeEnvelope          string `json:"scope_envelope"`
	GrantEnvelope          string `json:"grant_envelope"`
}
type VaultTeamMember struct {
	ENVPermission        string `json:"env_permission"`
	AccountID            string `json:"account_id"`
	MembershipGeneration uint64 `json:"membership_generation"`
	Role                 string `json:"role"`
	Active               bool   `json:"active"`
	GrantEpoch           uint64 `json:"grant_epoch"`
}
type VaultTeamState struct {
	RotationRequired bool              `json:"rotation_required"`
	TeamID           string            `json:"team_id"`
	OwnerAccount     string            `json:"owner_account"`
	Generation       uint64            `json:"generation"`
	KeyEpoch         uint64            `json:"key_epoch"`
	Members          []VaultTeamMember `json:"members"`
	Scope            VaultScopeState   `json:"scope"`
}
type VaultMemberGrant struct {
	OperationID                  string `json:"operation_id"`
	AccountID                    string `json:"account_id"`
	ExpectedTeamGeneration       uint64 `json:"expected_team_generation"`
	ExpectedMembershipGeneration uint64 `json:"expected_membership_generation"`
	GrantEnvelope                string `json:"grant_envelope"`
}
type VaultTeamRotate struct {
	ConfirmTotalLoss       bool     `json:"confirm_total_loss,omitempty"`
	VaultEnvelope          string   `json:"vault_envelope"`
	OperationID            string   `json:"operation_id"`
	ExpectedTeamGeneration uint64   `json:"expected_team_generation"`
	RemoveAccountIDs       []string `json:"remove_account_ids"`
	ScopeEnvelope          string   `json:"scope_envelope"`
	GrantEnvelopes         []string `json:"grant_envelopes"`
}
type VaultGrantState struct {
	SenderWriterPublic   string `json:"sender_writer_public"`
	TeamID               string `json:"team_id"`
	MembershipGeneration uint64 `json:"membership_generation"`
	TeamEpoch            uint64 `json:"team_epoch"`
	DocumentID           string `json:"document_id"`
	Envelope             string `json:"envelope"`
}
type VaultSharingState struct {
	AccountID       string `json:"account_id"`
	VaultGeneration uint64 `json:"vault_generation"`
	WriterPublic    string `json:"writer_public"`
	SharingPublic   string `json:"sharing_public"`
}
type VaultPersonalReset struct {
	OperationID             string   `json:"operation_id"`
	ExpectedVaultDocumentID string   `json:"expected_vault_document_id"`
	VaultEnvelope           string   `json:"vault_envelope"`
	ScopeEnvelopes          []string `json:"scope_envelopes"`
	ConfirmTotalLoss        bool     `json:"confirm_total_loss"`
}

type vaultScopeHeader struct {
	_                     struct{} `cbor:",toarray"`
	Domain                string
	Version               uint64
	Issuer                string
	OwnerKind             string
	OwnerID               string
	MachineID             string
	KeyEpoch              uint64
	Revision              uint64
	Previous              []byte
	WriterAccount         string
	WriterVaultGeneration uint64
	Nonce                 []byte
}
type vaultScopeEnvelope struct {
	_          struct{} `cbor:",toarray"`
	Header     []byte
	Ciphertext []byte
	Signature  []byte
}
type parsedVaultScope struct {
	Header vaultScopeHeader
	State  VaultScopeState
	Raw    []byte
}
type vaultTeamGrantClaims struct {
	_                        struct{} `cbor:",toarray"`
	Domain                   string
	Version                  uint64
	Issuer                   string
	TeamID                   string
	TeamEpoch                uint64
	MembershipGeneration     uint64
	SenderAccount            string
	SenderWriterPublic       []byte
	RecipientAccount         string
	RecipientVaultGeneration uint64
	RecipientSharingPublic   []byte
	OperationID              string
}
type vaultTeamGrantEnvelope struct {
	_          struct{} `cbor:",toarray"`
	Claims     []byte
	Enc        []byte
	Ciphertext []byte
	Signature  []byte
}
type parsedVaultGrant struct {
	Claims vaultTeamGrantClaims
	State  VaultGrantState
	Raw    []byte
}

func decodeVaultCanonical(raw []byte, maximum int, out any) bool {
	if len(raw) == 0 || len(raw) > maximum || !canonical(raw) || strictDecoding.Unmarshal(raw, out) != nil {
		return false
	}
	encoded, err := canonicalEncoding.Marshal(out)
	return err == nil && bytes.Equal(raw, encoded)
}
func parseVaultScope(raw []byte, issuer string, writer PasswordVaultMetadata) (parsedVaultScope, error) {
	var env vaultScopeEnvelope
	var h vaultScopeHeader
	var out parsedVaultScope
	if !decodeVaultCanonical(raw, MaximumVaultScopeBytes, &env) || !decodeVaultCanonical(env.Header, 2048, &h) || h.Domain != "paperboat.environment.vault-scope" || h.Version != 1 || h.Issuer != issuer || !validIdentifier(h.OwnerID) || (h.OwnerKind != "personal" && h.OwnerKind != "team") || (h.MachineID != "" && !validIdentifier(h.MachineID)) || (h.OwnerKind == "team" && h.MachineID != "") || !validCounter(h.KeyEpoch) || !validCounter(h.Revision) || !validCounter(h.WriterVaultGeneration) || len(h.Previous) != 32 || (h.Revision == 1) != allZeroBytes(h.Previous) || len(h.Nonce) != 12 || len(env.Ciphertext) <= 16 || len(env.Ciphertext) > (256<<10)+16 || len(env.Signature) != 64 || h.WriterAccount != writer.Head.AccountID || h.WriterVaultGeneration != writer.Head.Generation {
		return out, ErrProtocolInvalid
	}
	message, err := canonicalEncoding.Marshal([]any{"paperboat.environment.vault-scope-signature", uint64(1), env.Header, env.Ciphertext})
	if err != nil || !ed25519.Verify(writer.WriterPublicKey[:], message, env.Signature) {
		return out, ErrProtocolSignature
	}
	digest := sha256.Sum256(raw)
	out = parsedVaultScope{Header: h, Raw: bytes.Clone(raw), State: VaultScopeState{WriterPublic: base64.RawURLEncoding.EncodeToString(writer.WriterPublicKey[:]), OwnerKind: h.OwnerKind, OwnerID: h.OwnerID, MachineID: h.MachineID, KeyEpoch: h.KeyEpoch, Revision: h.Revision, DocumentID: digestText(digest[:]), Envelope: base64.RawURLEncoding.EncodeToString(raw)}}
	return out, nil
}
func parseVaultGrant(raw []byte, issuer string, sender, recipient PasswordVaultMetadata) (parsedVaultGrant, error) {
	var env vaultTeamGrantEnvelope
	var c vaultTeamGrantClaims
	var out parsedVaultGrant
	if !decodeVaultCanonical(raw, MaximumTeamGrantBytes, &env) || !decodeVaultCanonical(env.Claims, 2048, &c) || c.Domain != "paperboat.environment.team-grant" || c.Version != 1 || c.Issuer != issuer || !validIdentifier(c.TeamID) || !validCounter(c.TeamEpoch) || !validCounter(c.MembershipGeneration) || c.SenderAccount != sender.Head.AccountID || !bytes.Equal(c.SenderWriterPublic, sender.WriterPublicKey[:]) || c.RecipientAccount != recipient.Head.AccountID || c.RecipientVaultGeneration != recipient.Head.Generation || !bytes.Equal(c.RecipientSharingPublic, recipient.SharingPublicKey[:]) || !validIdentifier(c.OperationID) || len(env.Enc) != 32 || len(env.Ciphertext) != 48 || len(env.Signature) != 64 {
		return out, ErrProtocolInvalid
	}
	message, err := canonicalEncoding.Marshal([]any{"paperboat.environment.team-grant-signature", uint64(1), env.Claims, env.Enc, env.Ciphertext})
	if err != nil || !ed25519.Verify(sender.WriterPublicKey[:], message, env.Signature) {
		return out, ErrProtocolSignature
	}
	digest := sha256.Sum256(raw)
	out = parsedVaultGrant{Claims: c, Raw: bytes.Clone(raw), State: VaultGrantState{SenderWriterPublic: base64.RawURLEncoding.EncodeToString(sender.WriterPublicKey[:]), TeamID: c.TeamID, MembershipGeneration: c.MembershipGeneration, TeamEpoch: c.TeamEpoch, DocumentID: digestText(digest[:]), Envelope: base64.RawURLEncoding.EncodeToString(raw)}}
	return out, nil
}

type VaultPersonalScopes struct {
	RotationRequired bool              `json:"rotation_required"`
	KeyEpoch         uint64            `json:"key_epoch"`
	Scopes           []VaultScopeState `json:"scopes"`
}

type VaultPersonalRotate struct {
	OperationID             string               `json:"operation_id"`
	ExpectedVaultDocumentID string               `json:"expected_vault_document_id"`
	VaultEnvelope           string               `json:"vault_envelope"`
	ScopeDocuments          []VaultScopeDocument `json:"scope_documents"`
}
type VaultScopeDocument struct {
	MachineID  string `json:"machine_id"`
	DocumentID string `json:"document_id"`
}
type VaultPersonalScopeStage struct {
	ExpectedVaultDocumentID string `json:"expected_vault_document_id"`
	MachineID               string `json:"machine_id"`
	Envelope                string `json:"envelope"`
}
