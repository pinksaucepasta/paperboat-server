package environment

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

func vaultScopeFixture(t *testing.T, h vaultScopeHeader, seed byte) []byte {
	t.Helper()
	header, err := EncodeCanonical(h)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := bytes.Repeat([]byte{5}, 48)
	message, _ := EncodeCanonical([]any{"paperboat.environment.vault-scope-signature", uint64(1), header, ciphertext})
	raw, err := EncodeCanonical(vaultScopeEnvelope{Header: header, Ciphertext: ciphertext, Signature: ed25519.Sign(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32)), message)})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func vaultGrantFixture(t *testing.T, c vaultTeamGrantClaims, seed byte) []byte {
	t.Helper()
	claims, err := EncodeCanonical(c)
	if err != nil {
		t.Fatal(err)
	}
	enc, ciphertext := bytes.Repeat([]byte{4}, 32), bytes.Repeat([]byte{5}, 48)
	message, _ := EncodeCanonical([]any{"paperboat.environment.team-grant-signature", uint64(1), claims, enc, ciphertext})
	raw, err := EncodeCanonical(vaultTeamGrantEnvelope{Claims: claims, Enc: enc, Ciphertext: ciphertext, Signature: ed25519.Sign(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32)), message)})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func fixtureScopeHeader(owner, kind, writer string, generation, epoch, revision uint64, previous []byte) vaultScopeHeader {
	return vaultScopeHeader{Domain: "paperboat.environment.vault-scope", Version: 1, Issuer: "https://control.example", OwnerKind: kind, OwnerID: owner, KeyEpoch: epoch, Revision: revision, Previous: previous, WriterAccount: writer, WriterVaultGeneration: generation, Nonce: bytes.Repeat([]byte{6}, 12)}
}
func fixtureGrantClaims(team, op string, epoch, membership uint64, sender, recipient PasswordVaultMetadata) vaultTeamGrantClaims {
	return vaultTeamGrantClaims{Domain: "paperboat.environment.team-grant", Version: 1, Issuer: "https://control.example", TeamID: team, TeamEpoch: epoch, MembershipGeneration: membership, SenderAccount: sender.Head.AccountID, SenderWriterPublic: sender.WriterPublicKey[:], RecipientAccount: recipient.Head.AccountID, RecipientVaultGeneration: recipient.Head.Generation, RecipientSharingPublic: recipient.SharingPublicKey[:], OperationID: op}
}
func fixtureVaultMetadata(t *testing.T, account string, generation uint64, previous []byte) PasswordVaultMetadata {
	t.Helper()
	raw := passwordVaultFixture(t, "https://control.example", account, generation, previous)
	m, err := ParsePasswordVaultMetadata(raw, "https://control.example", account)
	if err != nil {
		t.Fatal(err)
	}
	return m
}
func TestVaultScopeSignatureAndCoordinates(t *testing.T) {
	writer := fixtureVaultMetadata(t, "user_a", 1, make([]byte, 32))
	h := fixtureScopeHeader("user_a", "personal", "user_a", 1, 1, 1, make([]byte, 32))
	raw := vaultScopeFixture(t, h, 11)
	parsed, err := parseVaultScope(raw, h.Issuer, writer)
	if err != nil || parsed.State.WriterPublic == "" {
		t.Fatal("valid signed scope rejected", err)
	}
	for _, change := range []string{"issuer", "writer", "generation", "signature", "kind", "team_machine", "previous", "nonce", "bound"} {
		t.Run(change, func(t *testing.T) {
			modified := h
			seed := byte(11)
			switch change {
			case "issuer":
				modified.Issuer = "https://other.example"
			case "writer":
				modified.WriterAccount = "user_b"
			case "generation":
				modified.WriterVaultGeneration++
			case "signature":
				seed = 12
			case "kind":
				modified.OwnerKind = "global"
			case "team_machine":
				modified.OwnerKind = "team"
				modified.MachineID = "host_a"
			case "previous":
				modified.Previous = bytes.Repeat([]byte{9}, 32)
			case "nonce":
				modified.Nonce = make([]byte, 13)
			case "bound":
				modified.Revision = MaxBrowserInteger + 1
			}
			if _, err := parseVaultScope(vaultScopeFixture(t, modified, seed), h.Issuer, writer); err == nil {
				t.Fatal("accepted invalid scope")
			}
		})
	}
	digest := sha256.Sum256(raw)
	next := parsed
	next.Header.Revision = 2
	next.Header.Previous = digest[:]
	if !scopeSuccessor(parsed.State, true, next, 1) {
		t.Fatal("valid successor rejected")
	}
	next.Header.KeyEpoch = 2
	if scopeSuccessor(parsed.State, true, next, 0) {
		t.Fatal("ordinary write changed key epoch")
	}
	if !scopeSuccessor(parsed.State, true, next, 2) {
		t.Fatal("rotation successor rejected")
	}
	var envelope vaultScopeEnvelope
	_ = strictDecoding.Unmarshal(raw, &envelope)
	envelope.Ciphertext[0] ^= 1
	raw, _ = EncodeCanonical(envelope)
	if _, err := parseVaultScope(raw, h.Issuer, writer); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}
}
func TestVaultGrantBindsExactRecipientsAndSender(t *testing.T) {
	sender := fixtureVaultMetadata(t, "user_a", 1, make([]byte, 32))
	recipient := fixtureVaultMetadata(t, "user_b", 1, make([]byte, 32))
	claims := fixtureGrantClaims("team_a", "op_a", 1, 1, sender, recipient)
	parsed, err := parseVaultGrant(vaultGrantFixture(t, claims, 11), claims.Issuer, sender, recipient)
	if err != nil || parsed.State.SenderWriterPublic == "" {
		t.Fatal("valid grant rejected", err)
	}
	for _, change := range []string{"issuer", "sender", "recipient", "public", "generation", "signature", "epoch"} {
		t.Run(change, func(t *testing.T) {
			c := claims
			seed := byte(11)
			switch change {
			case "issuer":
				c.Issuer = "https://other.example"
			case "sender":
				c.SenderAccount = "user_b"
			case "recipient":
				c.RecipientAccount = "user_a"
			case "public":
				c.RecipientSharingPublic = bytes.Repeat([]byte{8}, 32)
			case "generation":
				c.RecipientVaultGeneration++
			case "signature":
				seed = 12
			case "epoch":
				c.TeamEpoch = 0
			}
			if _, err := parseVaultGrant(vaultGrantFixture(t, c, seed), claims.Issuer, sender, recipient); err == nil {
				t.Fatal("accepted substituted grant")
			}
		})
	}
}
func b64Vault(raw []byte) string { return base64.RawURLEncoding.EncodeToString(raw) }

func TestVaultTeamRotationAuthorization(t *testing.T) {
	team := VaultTeamState{OwnerAccount: "owner", KeyEpoch: 2, RotationRequired: true, Members: []VaultTeamMember{
		{AccountID: "owner", Role: "owner", Active: true, GrantEpoch: 2, ENVPermission: "write"},
		{AccountID: "admin", Role: "admin", Active: true, GrantEpoch: 2, ENVPermission: "write"},
		{AccountID: "member", Role: "member", Active: true, GrantEpoch: 2, ENVPermission: "write"},
		{AccountID: "pending", Role: "admin", Active: true},
		{AccountID: "removed", Role: "admin", GrantEpoch: 2},
		{AccountID: "revoked-member", Role: "member"},
	}}
	for _, tc := range []struct {
		name, account string
		request       VaultTeamRotate
		want          bool
	}{
		{"owner rotation", "owner", VaultTeamRotate{}, true},
		{"admin rotation", "admin", VaultTeamRotate{}, true},
		{"member rotation denied", "member", VaultTeamRotate{}, false},
		{"member reset denied", "member", VaultTeamRotate{ConfirmTotalLoss: true}, false},
		{"admin reset denied", "admin", VaultTeamRotate{ConfirmTotalLoss: true}, false},
		{"admin remove owner denied", "admin", VaultTeamRotate{RemoveAccountIDs: []string{"owner"}}, false},
		{"admin remove admin denied", "admin", VaultTeamRotate{RemoveAccountIDs: []string{"pending"}}, false},
		{"admin finish revoked member rekey", "admin", VaultTeamRotate{RemoveAccountIDs: []string{"revoked-member"}}, true},
		{"admin remove member", "admin", VaultTeamRotate{RemoveAccountIDs: []string{"member"}}, true},
		{"role without key denied", "pending", VaultTeamRotate{}, false},
		{"key without membership denied", "removed", VaultTeamRotate{}, false},
		{"unknown denied", "unknown", VaultTeamRotate{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := vaultTeamRotationAllowed(team, tc.account, tc.request); got != tc.want {
				t.Fatalf("authorization = %v, want %v", got, tc.want)
			}
		})
	}
	team.Members[0].GrantEpoch = 0
	if !vaultTeamRotationAllowed(team, "owner", VaultTeamRotate{ConfirmTotalLoss: true}) {
		t.Fatal("explicit owner total loss reset unavailable")
	}
}
