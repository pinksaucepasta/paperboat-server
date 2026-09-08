package environment

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"testing"
)

type vaultFixtureOptions struct {
	passwordEpoch         uint64
	recoveryEpoch         uint64
	recovery              bool
	passwordSaltByte      byte
	recoveryRecipientByte byte
	writerSeedByte        byte
	ciphertextByte        byte
}

func passwordVaultFixture(t *testing.T, issuer, account string, generation uint64, previous []byte) []byte {
	return passwordVaultFixtureWith(t, issuer, account, generation, previous, vaultFixtureOptions{})
}

func passwordVaultFixtureByte(t *testing.T, issuer, account string, generation uint64, previous []byte, ciphertextByte byte) []byte {
	return passwordVaultFixtureWith(t, issuer, account, generation, previous, vaultFixtureOptions{ciphertextByte: ciphertextByte})
}

func passwordVaultFixtureWith(t *testing.T, issuer, account string, generation uint64, previous []byte, opts vaultFixtureOptions) []byte {
	t.Helper()
	if opts.passwordEpoch == 0 {
		opts.passwordEpoch = 1
	}
	if opts.recoveryEpoch == 0 {
		opts.recoveryEpoch = 1
	}
	if opts.writerSeedByte == 0 {
		opts.writerSeedByte = 11
	}
	if opts.ciphertextByte == 0 {
		opts.ciphertextByte = 3
	}
	writerPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{opts.writerSeedByte}, ed25519.SeedSize))
	writerPublic := writerPrivate.Public().(ed25519.PublicKey)
	descriptor := func(kind, epoch, profile uint64, salt []byte, recipientByte, signingSeedByte byte) passwordVaultDescriptor {
		signingPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{signingSeedByte}, ed25519.SeedSize))
		signingPublic := signingPrivate.Public().(ed25519.PublicKey)
		recipient := bytes.Repeat([]byte{recipientByte}, 32)
		contextBytes, err := EncodeCanonical([]any{"paperboat.environment.vault-credential", uint64(1), issuer, account, kind, epoch, profile, salt})
		if err != nil {
			t.Fatal(err)
		}
		message, err := EncodeCanonical([]any{"paperboat.environment.vault-delegation", uint64(1), contextBytes, recipient, signingPublic, writerPublic})
		if err != nil {
			t.Fatal(err)
		}
		return passwordVaultDescriptor{Kind: kind, Epoch: epoch, Profile: profile, Salt: salt, RecipientPublic: recipient, CredentialSignPublic: signingPublic, DelegationSignature: ed25519.Sign(signingPrivate, message)}
	}
	password := descriptor(1, opts.passwordEpoch, 1, bytes.Repeat([]byte{opts.passwordSaltByte + 1}, 16), 21, 31)
	var recovery *passwordVaultDescriptor
	recoveryWrap := []byte{}
	if opts.recovery {
		value := descriptor(2, opts.recoveryEpoch, 0, []byte{}, opts.recoveryRecipientByte+41, 51)
		recovery = &value
		recoveryWrap = bytes.Repeat([]byte{61}, 80)
	}
	header := passwordVaultHeader{Domain: "paperboat.environment.password-vault", Version: 1, Issuer: issuer, AccountID: account, Generation: generation, Previous: previous, WriterPublic: writerPublic, PasswordDescriptor: password, RecoveryEpoch: opts.recoveryEpoch, RecoveryDescriptor: recovery, PayloadNonce: bytes.Repeat([]byte{71}, 12), SharingPublic: bytes.Repeat([]byte{72}, 32)}
	headerRaw, err := EncodeCanonical(header)
	if err != nil {
		t.Fatal(err)
	}
	bodyRaw, err := EncodeCanonical(passwordVaultBody{Header: headerRaw, PasswordWrap: bytes.Repeat([]byte{81}, 80), RecoveryWrap: recoveryWrap, Ciphertext: bytes.Repeat([]byte{opts.ciphertextByte}, 17)})
	if err != nil {
		t.Fatal(err)
	}
	signatureMessage, err := EncodeCanonical([]any{"paperboat.environment.vault-signature", uint64(1), bodyRaw})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := EncodeCanonical(passwordVaultEnvelope{UnsignedBody: bodyRaw, Signature: ed25519.Sign(writerPrivate, signatureMessage)})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestParsePasswordVaultAuthenticatesUnifiedEnvelope(t *testing.T) {
	raw := passwordVaultFixtureWith(t, "https://control.example", "account_1", 1, make([]byte, 32), vaultFixtureOptions{recovery: true})
	metadata, err := ParsePasswordVaultMetadata(raw, "https://control.example", "account_1")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	if metadata.Head.Generation != 1 || metadata.Head.DocumentID != digestText(digest[:]) ||
		metadata.PasswordEpoch != 1 || metadata.RecoveryEpoch != 1 || !metadata.RecoveryEnabled ||
		metadata.SharingPublicKey != [32]byte{72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72, 72} ||
		!allZeroBytes(metadata.PreviousDigest[:]) {
		t.Fatalf("unexpected metadata: %+v", metadata)
	}
	for name, binding := range map[string][2]string{
		"issuer substitution":  {"https://other.example", "account_1"},
		"account substitution": {"https://control.example", "account_2"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParsePasswordVaultMetadata(raw, binding[0], binding[1]); err == nil {
				t.Fatal("accepted substitution")
			}
		})
	}
}

func TestParsePasswordVaultRejectsForgeryAndMalformedDescriptors(t *testing.T) {
	raw := passwordVaultFixture(t, "https://control.example", "account_1", 1, make([]byte, 32))
	var envelope passwordVaultEnvelope
	if err := strictDecoding.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope.Signature[0] ^= 1
	forged, _ := EncodeCanonical(envelope)
	if _, err := ParsePasswordVaultMetadata(forged, "https://control.example", "account_1"); !errors.Is(err, ErrProtocolSignature) {
		t.Fatalf("writer forgery error=%v", err)
	}

	var body passwordVaultBody
	if err := strictDecoding.Unmarshal(envelope.UnsignedBody, &body); err != nil {
		t.Fatal(err)
	}
	var header passwordVaultHeader
	if err := strictDecoding.Unmarshal(body.Header, &header); err != nil {
		t.Fatal(err)
	}
	header.PasswordDescriptor.DelegationSignature[0] ^= 1
	body.Header, _ = EncodeCanonical(header)
	envelope.UnsignedBody, _ = EncodeCanonical(body)
	message, _ := EncodeCanonical([]any{"paperboat.environment.vault-signature", uint64(1), envelope.UnsignedBody})
	writerPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{11}, ed25519.SeedSize))
	envelope.Signature = ed25519.Sign(writerPrivate, message)
	forged, _ = EncodeCanonical(envelope)
	if _, err := ParsePasswordVaultMetadata(forged, "https://control.example", "account_1"); err == nil {
		t.Fatal("accepted credential delegation forgery with a valid writer signature")
	}
}

func TestPasswordVaultSuccessorEpochRules(t *testing.T) {
	issuer, account := "https://control.example", "account_1"
	firstRaw := passwordVaultFixture(t, issuer, account, 1, make([]byte, 32))
	first, err := parsePasswordVault(firstRaw, issuer, account)
	if err != nil {
		t.Fatal(err)
	}
	previous := sha256.Sum256(firstRaw)
	tests := []struct {
		name    string
		options vaultFixtureOptions
		valid   bool
	}{
		{"payload only", vaultFixtureOptions{ciphertextByte: 4}, true},
		{"password changed with next epoch", vaultFixtureOptions{passwordEpoch: 2, passwordSaltByte: 2}, true},
		{"password changed without epoch", vaultFixtureOptions{passwordSaltByte: 2}, false},
		{"password descriptor reissued at next epoch", vaultFixtureOptions{passwordEpoch: 2}, true},
		{"enable recovery", vaultFixtureOptions{recovery: true, recoveryEpoch: 2}, true},
		{"enable recovery stale epoch", vaultFixtureOptions{recovery: true}, false},
		{"writer rotation", vaultFixtureOptions{writerSeedByte: 12}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw := passwordVaultFixtureWith(t, issuer, account, 2, previous[:], tc.options)
			next, err := parsePasswordVault(raw, issuer, account)
			if err != nil {
				t.Fatal(err)
			}
			if got := validPasswordVaultSuccessor(first, next); got != tc.valid {
				t.Fatalf("valid=%v want %v", got, tc.valid)
			}
		})
	}
}

func TestPasswordVaultRecoveryEnableReplaceDisableEpochRules(t *testing.T) {
	issuer, account := "https://control.example", "account_1"
	raw := passwordVaultFixture(t, issuer, account, 1, make([]byte, 32))
	disabled, err := parsePasswordVault(raw, issuer, account)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	raw = passwordVaultFixtureWith(t, issuer, account, 2, digest[:], vaultFixtureOptions{recovery: true, recoveryEpoch: 2})
	enabled, err := parsePasswordVault(raw, issuer, account)
	if err != nil || !validPasswordVaultSuccessor(disabled, enabled) {
		t.Fatalf("enable rejected: %v", err)
	}
	digest = sha256.Sum256(raw)
	raw = passwordVaultFixtureWith(t, issuer, account, 3, digest[:], vaultFixtureOptions{recovery: true, recoveryEpoch: 3, recoveryRecipientByte: 1})
	replaced, err := parsePasswordVault(raw, issuer, account)
	if err != nil || !validPasswordVaultSuccessor(enabled, replaced) {
		t.Fatalf("replace rejected: %v", err)
	}
	digest = sha256.Sum256(raw)
	raw = passwordVaultFixtureWith(t, issuer, account, 4, digest[:], vaultFixtureOptions{recoveryEpoch: 4})
	disabledAgain, err := parsePasswordVault(raw, issuer, account)
	if err != nil || !validPasswordVaultSuccessor(replaced, disabledAgain) {
		t.Fatalf("disable rejected: %v", err)
	}
}

func TestParsePasswordVaultRejectsBoundsAndRecoveryInconsistency(t *testing.T) {
	if _, err := ParsePasswordVaultMetadata(bytes.Repeat([]byte{0}, MaximumPasswordVaultBytes+1), "https://control.example", "account_1"); err == nil {
		t.Fatal("accepted oversized envelope")
	}
	raw := passwordVaultFixture(t, "https://control.example", "account_1", 1, make([]byte, 32))
	var envelope passwordVaultEnvelope
	_ = strictDecoding.Unmarshal(raw, &envelope)
	var body passwordVaultBody
	_ = strictDecoding.Unmarshal(envelope.UnsignedBody, &body)
	body.RecoveryWrap = bytes.Repeat([]byte{1}, 80)
	envelope.UnsignedBody, _ = EncodeCanonical(body)
	envelope.Signature = bytes.Repeat([]byte{1}, 64)
	inconsistent, _ := EncodeCanonical(envelope)
	if _, err := ParsePasswordVaultMetadata(inconsistent, "https://control.example", "account_1"); err == nil {
		t.Fatal("accepted recovery wrap without descriptor")
	}
}
