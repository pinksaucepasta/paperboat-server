package environment

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"slices"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/pinksaucepasta/paperboat-server/internal/db"
)

const MaximumPasswordVaultBytes = (256 << 10) + (2 << 10)

var ErrPasswordVaultConflict = errors.New("environment password vault changed")

type PasswordVaultHead struct {
	Issuer     string `json:"issuer"`
	AccountID  string `json:"account_id"`
	Generation uint64 `json:"generation"`
	DocumentID string `json:"document_id"`
	Envelope   string `json:"envelope"`
}

// PasswordVaultMetadata is authenticated public transition state. It contains
// no password, recovery seed, decrypted key, or private writer material.
type PasswordVaultMetadata struct {
	Head             PasswordVaultHead
	PreviousDigest   [sha256.Size]byte
	WriterPublicKey  [ed25519.PublicKeySize]byte
	PasswordEpoch    uint64
	RecoveryEpoch    uint64
	RecoveryEnabled  bool
	SharingPublicKey [32]byte
}

type passwordVaultDescriptor struct {
	_                    struct{} `cbor:",toarray"`
	Kind                 uint64
	Epoch                uint64
	Profile              uint64
	Salt                 []byte
	RecipientPublic      []byte
	CredentialSignPublic []byte
	DelegationSignature  []byte
}
type passwordVaultHeader struct {
	_                  struct{} `cbor:",toarray"`
	Domain             string
	Version            uint64
	Issuer             string
	AccountID          string
	Generation         uint64
	Previous           []byte
	WriterPublic       []byte
	PasswordDescriptor passwordVaultDescriptor
	RecoveryEpoch      uint64
	RecoveryDescriptor *passwordVaultDescriptor
	PayloadNonce       []byte
	SharingPublic      []byte
}
type passwordVaultBody struct {
	_            struct{} `cbor:",toarray"`
	Header       []byte
	PasswordWrap []byte
	RecoveryWrap []byte
	Ciphertext   []byte
}
type passwordVaultEnvelope struct {
	_            struct{} `cbor:",toarray"`
	UnsignedBody []byte
	Signature    []byte
}
type parsedPasswordVault struct {
	metadata           PasswordVaultMetadata
	passwordDescriptor []byte
	recoveryDescriptor []byte
	raw                []byte
}

func ParsePasswordVault(raw []byte, issuer, accountID string) (PasswordVaultHead, [sha256.Size]byte, error) {
	parsed, err := parsePasswordVault(raw, issuer, accountID)
	return parsed.metadata.Head, parsed.metadata.PreviousDigest, err
}

// ParsePasswordVaultMetadata validates the full canonical envelope and returns
// the public fields used by clients and the server's successor checks.
func ParsePasswordVaultMetadata(raw []byte, issuer, accountID string) (PasswordVaultMetadata, error) {
	parsed, err := parsePasswordVault(raw, issuer, accountID)
	return parsed.metadata, err
}

func parsePasswordVault(raw []byte, issuer, accountID string) (parsedPasswordVault, error) {
	var out parsedPasswordVault
	if len(raw) == 0 || len(raw) > MaximumPasswordVaultBytes || len(issuer) == 0 ||
		len(issuer) > 1024 || !utf8.ValidString(issuer) || !validIdentifier(accountID) || !canonical(raw) {
		return out, ErrProtocolInvalid
	}
	var envelope passwordVaultEnvelope
	if strictDecoding.Unmarshal(raw, &envelope) != nil || len(envelope.UnsignedBody) == 0 ||
		len(envelope.Signature) != ed25519.SignatureSize || !canonical(envelope.UnsignedBody) {
		return out, ErrProtocolInvalid
	}
	if encoded, err := canonicalEncoding.Marshal(envelope); err != nil || !bytes.Equal(encoded, raw) {
		return out, ErrProtocolInvalid
	}
	var body passwordVaultBody
	if strictDecoding.Unmarshal(envelope.UnsignedBody, &body) != nil || len(body.Header) == 0 ||
		len(body.Header) > 2048 || !canonical(body.Header) || len(body.PasswordWrap) != 80 ||
		body.RecoveryWrap == nil || (len(body.RecoveryWrap) != 0 && len(body.RecoveryWrap) != 80) ||
		len(body.Ciphertext) <= 16 || len(body.Ciphertext) > (256<<10)+16 {
		return out, ErrProtocolInvalid
	}
	if encoded, err := canonicalEncoding.Marshal(body); err != nil || !bytes.Equal(encoded, envelope.UnsignedBody) {
		return out, ErrProtocolInvalid
	}
	var header passwordVaultHeader
	if strictDecoding.Unmarshal(body.Header, &header) != nil ||
		header.Domain != "paperboat.environment.password-vault" || header.Version != 1 ||
		header.Issuer != issuer || header.AccountID != accountID || !validCounter(header.Generation) ||
		len(header.Previous) != sha256.Size || len(header.WriterPublic) != ed25519.PublicKeySize ||
		!validCounter(header.RecoveryEpoch) || len(header.PayloadNonce) != 12 ||
		!validX25519Public(header.SharingPublic) ||
		(header.Generation == 1) != allZeroBytes(header.Previous) {
		return out, ErrProtocolInvalid
	}
	if encoded, err := canonicalEncoding.Marshal(header); err != nil || !bytes.Equal(encoded, body.Header) {
		return out, ErrProtocolInvalid
	}
	if !validVaultDescriptor(header.PasswordDescriptor, 1, issuer, accountID, header.WriterPublic) {
		return out, ErrProtocolInvalid
	}
	if header.RecoveryDescriptor == nil {
		if len(body.RecoveryWrap) != 0 {
			return out, ErrProtocolInvalid
		}
	} else if len(body.RecoveryWrap) != 80 ||
		header.RecoveryDescriptor.Epoch != header.RecoveryEpoch ||
		!validVaultDescriptor(*header.RecoveryDescriptor, 2, issuer, accountID, header.WriterPublic) {
		return out, ErrProtocolInvalid
	}
	signatureMessage, err := canonicalEncoding.Marshal([]any{"paperboat.environment.vault-signature", uint64(1), envelope.UnsignedBody})
	if err != nil || !ed25519.Verify(ed25519.PublicKey(header.WriterPublic), signatureMessage, envelope.Signature) {
		return out, ErrProtocolSignature
	}
	passwordDescriptor, err := canonicalEncoding.Marshal(header.PasswordDescriptor)
	if err != nil {
		return out, ErrProtocolInvalid
	}
	var recoveryDescriptor []byte
	if header.RecoveryDescriptor != nil {
		recoveryDescriptor, err = canonicalEncoding.Marshal(*header.RecoveryDescriptor)
		if err != nil {
			return out, ErrProtocolInvalid
		}
	}
	digest := sha256.Sum256(raw)
	copy(out.metadata.PreviousDigest[:], header.Previous)
	copy(out.metadata.WriterPublicKey[:], header.WriterPublic)
	copy(out.metadata.SharingPublicKey[:], header.SharingPublic)
	out.metadata.Head = PasswordVaultHead{Issuer: issuer, AccountID: accountID, Generation: header.Generation, DocumentID: digestText(digest[:]), Envelope: base64.RawURLEncoding.EncodeToString(raw)}
	out.metadata.PasswordEpoch = header.PasswordDescriptor.Epoch
	out.metadata.RecoveryEpoch = header.RecoveryEpoch
	out.metadata.RecoveryEnabled = header.RecoveryDescriptor != nil
	out.passwordDescriptor, out.recoveryDescriptor, out.raw = passwordDescriptor, recoveryDescriptor, slices.Clone(raw)
	return out, nil
}

func validX25519Public(raw []byte) bool {
	if len(raw) != 32 || allZeroBytes(raw) {
		return false
	}
	_, err := ecdh.X25519().NewPublicKey(raw)
	return err == nil
}

func validVaultDescriptor(d passwordVaultDescriptor, kind uint64, issuer, accountID string, writerPublic []byte) bool {
	if d.Kind != kind || !validCounter(d.Epoch) || !validX25519Public(d.RecipientPublic) ||
		len(d.CredentialSignPublic) != ed25519.PublicKeySize || len(d.DelegationSignature) != ed25519.SignatureSize {
		return false
	}
	if (kind == 1 && (d.Profile != 1 || len(d.Salt) != 16)) ||
		(kind == 2 && (d.Profile != 0 || d.Salt == nil || len(d.Salt) != 0)) {
		return false
	}
	contextBytes, err := canonicalEncoding.Marshal([]any{"paperboat.environment.vault-credential", uint64(1), issuer, accountID, kind, d.Epoch, d.Profile, d.Salt})
	if err != nil {
		return false
	}
	delegation, err := canonicalEncoding.Marshal([]any{"paperboat.environment.vault-delegation", uint64(1), contextBytes, d.RecipientPublic, d.CredentialSignPublic, writerPublic})
	return err == nil && ed25519.Verify(ed25519.PublicKey(d.CredentialSignPublic), delegation, d.DelegationSignature)
}

func validPasswordVaultSuccessor(previous, incoming parsedPasswordVault) bool {
	if previous.metadata.WriterPublicKey != incoming.metadata.WriterPublicKey {
		return false
	}
	passwordChanged := !bytes.Equal(previous.passwordDescriptor, incoming.passwordDescriptor)
	wantPasswordEpoch := previous.metadata.PasswordEpoch
	if passwordChanged {
		wantPasswordEpoch++
	}
	if wantPasswordEpoch > MaxBrowserInteger || incoming.metadata.PasswordEpoch != wantPasswordEpoch {
		return false
	}
	recoveryChanged := !bytes.Equal(previous.recoveryDescriptor, incoming.recoveryDescriptor)
	wantRecoveryEpoch := previous.metadata.RecoveryEpoch
	if recoveryChanged {
		wantRecoveryEpoch++
	}
	return wantRecoveryEpoch <= MaxBrowserInteger && incoming.metadata.RecoveryEpoch == wantRecoveryEpoch
}

func allZeroBytes(value []byte) bool {
	for _, b := range value {
		if b != 0 {
			return false
		}
	}
	return true
}

func (s *Service) PasswordVaultIssuer() string {
	return s.passwordVaultIssuer
}

func (s *Service) GetPasswordVault(ctx context.Context, accountID string) (PasswordVaultHead, error) {
	if s.passwordVaultIssuer == "" || !validIdentifier(accountID) {
		return PasswordVaultHead{}, ErrProtocolInvalid
	}
	var generation int64
	var documentID string
	var envelope []byte
	err := s.db.Pool().QueryRow(ctx, `SELECT generation,document_id,envelope FROM paperboat.environment_password_vaults WHERE account_id=$1`, accountID).Scan(&generation, &documentID, &envelope)
	if errors.Is(err, pgx.ErrNoRows) || errors.Is(err, sql.ErrNoRows) {
		return PasswordVaultHead{}, ErrNotFound
	}
	if err != nil {
		return PasswordVaultHead{}, err
	}
	parsed, err := parsePasswordVault(envelope, s.passwordVaultIssuer, accountID)
	if err != nil || parsed.metadata.Head.Generation != uint64(generation) || parsed.metadata.Head.DocumentID != documentID {
		return PasswordVaultHead{}, ErrProtocolInvalid
	}
	return parsed.metadata.Head, nil
}

func (s *Service) PutPasswordVault(ctx context.Context, accountID string, raw []byte) (PasswordVaultHead, error) {
	if s.passwordVaultIssuer == "" || !validIdentifier(accountID) {
		return PasswordVaultHead{}, ErrProtocolInvalid
	}
	incoming, err := parsePasswordVault(raw, s.passwordVaultIssuer, accountID)
	if err != nil {
		return PasswordVaultHead{}, err
	}
	err = s.db.InTx(ctx, func(ctx context.Context, tx *db.Tx) error {
		if err := lockAccountTx(ctx, tx, accountID); err != nil {
			return err
		}
		var generation int64
		var documentID string
		var existing []byte
		err := tx.QueryRow(ctx, `SELECT generation,document_id,envelope FROM environment_password_vaults WHERE account_id=$1 FOR UPDATE`, accountID).Scan(&generation, &documentID, &existing)
		if errors.Is(err, pgx.ErrNoRows) || errors.Is(err, sql.ErrNoRows) {
			if incoming.metadata.Head.Generation != 1 || !allZeroBytes(incoming.metadata.PreviousDigest[:]) ||
				incoming.metadata.PasswordEpoch != 1 || incoming.metadata.RecoveryEpoch != 1 {
				return ErrPasswordVaultConflict
			}
			_, err = tx.Exec(ctx, `INSERT INTO environment_password_vaults(account_id,generation,document_id,envelope) VALUES($1,$2,$3,$4)`, accountID, int64(incoming.metadata.Head.Generation), incoming.metadata.Head.DocumentID, incoming.raw)
			return err
		}
		if err != nil {
			return err
		}
		if documentID == incoming.metadata.Head.DocumentID && generation == int64(incoming.metadata.Head.Generation) && slices.Equal(existing, incoming.raw) {
			return nil
		}
		if incoming.metadata.Head.Generation != uint64(generation)+1 || digestText(incoming.metadata.PreviousDigest[:]) != documentID {
			return ErrPasswordVaultConflict
		}
		current, err := parsePasswordVault(existing, s.passwordVaultIssuer, accountID)
		if err != nil || current.metadata.Head.Generation != uint64(generation) || current.metadata.Head.DocumentID != documentID {
			return ErrProtocolInvalid
		}
		if !validPasswordVaultSuccessor(current, incoming) {
			return ErrPasswordVaultConflict
		}
		command, err := tx.Exec(ctx, `UPDATE environment_password_vaults SET generation=$2,document_id=$3,envelope=$4,updated_at=now() WHERE account_id=$1 AND generation=$5 AND document_id=$6`, accountID, int64(incoming.metadata.Head.Generation), incoming.metadata.Head.DocumentID, incoming.raw, generation, documentID)
		if err != nil {
			return err
		}
		if command.RowsAffected() != 1 {
			return ErrPasswordVaultConflict
		}
		return nil
	})
	return incoming.metadata.Head, err
}
