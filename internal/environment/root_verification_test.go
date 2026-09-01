package environment

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/pinksaucepasta/paperboat-server/internal/peeridentity"
)

func testVerificationRoot(t *testing.T, seedByte byte) (peeridentity.AccountKey, ed25519.PrivateKey) {
	t.Helper()
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seedByte}, ed25519.SeedSize))
	public := private.Public().(ed25519.PublicKey)
	fingerprint, err := peeridentity.RootFingerprint(public)
	if err != nil {
		t.Fatal(err)
	}
	return peeridentity.AccountKey{KeyID: "aek_" + fingerprint, PublicKey: append(ed25519.PublicKey(nil), public...)}, private
}

func signTestEnvironmentDocument(t *testing.T, contentType, keyID string, private ed25519.PrivateKey) []byte {
	return signTestEnvironmentPayload(t, contentType, keyID, private, []byte{0x80})
}

func signTestEnvironmentPayload(t *testing.T, contentType, keyID string, private ed25519.PrivateKey, payload []byte) []byte {
	t.Helper()
	protected, err := EncodeCanonical(map[int64]any{1: int64(-8), 3: contentType, 4: []byte(keyID)})
	if err != nil {
		t.Fatal(err)
	}
	toSign, err := EncodeCanonical([]any{"Signature1", protected, []byte{}, payload})
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(private, toSign)
	raw, err := EncodeCanonical(cbor.Tag{Number: 18, Content: []any{protected, map[any]any{}, payload, signature}})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func signTestEndpointCertificate(t *testing.T, private ed25519.PrivateKey, account, endpoint string, generation uint64, issued, expires time.Time) []byte {
	t.Helper()
	var payload bytes.Buffer
	payload.WriteString("PBEC")
	payload.WriteByte(1)
	writeString := func(value string) {
		if err := binary.Write(&payload, binary.BigEndian, uint16(len(value))); err != nil {
			t.Fatal(err)
		}
		payload.WriteString(value)
	}
	writeString(account)
	payload.WriteByte(byte(peeridentity.RoleMachine))
	writeString(endpoint)
	payload.Write(bytes.Repeat([]byte{1}, 32))
	payload.Write(bytes.Repeat([]byte{2}, 32))
	for _, value := range []uint64{generation, 1, uint64(issued.Unix()), uint64(expires.Unix())} {
		if err := binary.Write(&payload, binary.BigEndian, value); err != nil {
			t.Fatal(err)
		}
	}
	return append(payload.Bytes(), ed25519.Sign(private, payload.Bytes())...)
}

func signTestBinding(t *testing.T, private ed25519.PrivateKey, account, endpoint string, endpointCertificate []byte, recipient []byte, issued time.Time, keyID string) []byte {
	t.Helper()
	recipientID := validKeyIDForTest(t, "envk_", recipient)
	body, err := EncodeCanonical([]any{
		"paperboat.environment.key-binding", uint64(1), account, uint64(3), endpoint,
		uint64(1), uint64(1), endpointCertificate, nil, nil, recipient, recipientID,
		uint64(issued.Unix()), nil, uint64(1),
	})
	if err != nil {
		t.Fatal(err)
	}
	return signTestEnvironmentPayload(t, BindingContentType, keyID, private, body)
}

func TestSelectVerificationRootsIgnoresExtraLiveKeys(t *testing.T) {
	pinned, _ := testVerificationRoot(t, 1)
	extra, _ := testVerificationRoot(t, 2)
	selected, err := selectVerificationRoots(peeridentity.AccountRoot{Keys: []peeridentity.AccountKey{pinned, extra}}, peeridentity.AccountRoot{Keys: []peeridentity.AccountKey{pinned}})
	if err != nil {
		t.Fatal(err)
	}
	if len(selected.Keys) != 1 || selected.Keys[0].KeyID != pinned.KeyID || !bytes.Equal(selected.Keys[0].PublicKey, pinned.PublicKey) {
		t.Fatalf("selected verification roots = %#v, want only genesis-pinned root", selected.Keys)
	}
}

func TestExtraLiveRootCannotVerifyEnvironmentAuthorityOrBinding(t *testing.T) {
	pinned, _ := testVerificationRoot(t, 1)
	extra, extraPrivate := testVerificationRoot(t, 2)
	selected, err := selectVerificationRoots(peeridentity.AccountRoot{Keys: []peeridentity.AccountKey{pinned, extra}}, peeridentity.AccountRoot{Keys: []peeridentity.AccountKey{pinned}})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name        string
		contentType string
		parse       func([]byte, peeridentity.AccountRoot) error
	}{
		{name: "authority", contentType: AuthorityContentType, parse: func(raw []byte, roots peeridentity.AccountRoot) error {
			_, err := ParseAuthority(raw, roots)
			return err
		}},
		{name: "binding", contentType: BindingContentType, parse: func(raw []byte, roots peeridentity.AccountRoot) error {
			_, err := ParseBinding(raw, roots)
			return err
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw := signTestEnvironmentDocument(t, test.contentType, extra.KeyID, extraPrivate)
			if _, _, err := verifyCOSE(raw, test.contentType, map[string]ed25519.PublicKey{extra.KeyID: extra.PublicKey}); err != nil {
				t.Fatalf("test document was not signed by extra root: %v", err)
			}
			if err := test.parse(raw, selected); !errors.Is(err, ErrProtocolSignature) {
				t.Fatalf("extra root document error = %v, want %v", err, ErrProtocolSignature)
			}
		})
	}
}

func TestLiveEndpointRootVerifiesEmbeddedCertificateButNotEnvironmentCOSE(t *testing.T) {
	pinned, pinnedPrivate := testVerificationRoot(t, 5)
	extra, extraPrivate := testVerificationRoot(t, 6)
	live := peeridentity.AccountRoot{Keys: []peeridentity.AccountKey{pinned, extra}}
	issued := time.Unix(1_700_000_000, 0).UTC()
	endpointCertificate := signTestEndpointCertificate(t, extraPrivate, "acct_root_separation", "host_root_separation", 1, issued, issued.Add(time.Hour))
	binding := signTestBinding(t, pinnedPrivate, "acct_root_separation", "host_root_separation", endpointCertificate, bytes.Repeat([]byte{3}, 32), issued, pinned.KeyID)
	if _, err := ParseBinding(binding, peeridentity.AccountRoot{Keys: []peeridentity.AccountKey{pinned}}, live); err != nil {
		t.Fatalf("endpoint certificate signed by live root was rejected: %v", err)
	}

	liveBinding := signTestBinding(t, extraPrivate, "acct_root_separation", "host_root_separation", endpointCertificate, bytes.Repeat([]byte{3}, 32), issued, extra.KeyID)
	if _, err := ParseBinding(liveBinding, peeridentity.AccountRoot{Keys: []peeridentity.AccountKey{pinned}}, live); !errors.Is(err, ErrProtocolSignature) {
		t.Fatalf("live root binding error = %v, want %v", err, ErrProtocolSignature)
	}
	liveAuthority := signTestEnvironmentDocument(t, AuthorityContentType, extra.KeyID, extraPrivate)
	if _, err := ParseAuthority(liveAuthority, peeridentity.AccountRoot{Keys: []peeridentity.AccountKey{pinned}}, live); !errors.Is(err, ErrProtocolSignature) {
		t.Fatalf("live root authority error = %v, want %v", err, ErrProtocolSignature)
	}
}

func TestSelectVerificationRootsReturnsRootSetChangedForMissingOrChangedPinnedKey(t *testing.T) {
	pinned, _ := testVerificationRoot(t, 1)
	changed, _ := testVerificationRoot(t, 2)
	cases := []struct {
		name string
		live peeridentity.AccountRoot
	}{
		{name: "missing", live: peeridentity.AccountRoot{}},
		{name: "changed", live: peeridentity.AccountRoot{Keys: []peeridentity.AccountKey{{KeyID: pinned.KeyID, PublicKey: changed.PublicKey}}}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			_, err := selectVerificationRoots(test.live, peeridentity.AccountRoot{Keys: []peeridentity.AccountKey{pinned}})
			if !errors.Is(err, ErrRootSetChanged) {
				t.Fatalf("error = %v, want %v", err, ErrRootSetChanged)
			}
		})
	}
}

func TestSelectAuthoritySignerRootPinsOnlyGenesisSigner(t *testing.T) {
	signer, _ := testVerificationRoot(t, 3)
	extra, _ := testVerificationRoot(t, 4)
	selected, err := selectAuthoritySignerRoot(peeridentity.AccountRoot{Keys: []peeridentity.AccountKey{signer, extra}}, Authority{SignerKeyID: signer.KeyID})
	if err != nil {
		t.Fatal(err)
	}
	if selected.KeyID != signer.KeyID || !bytes.Equal(selected.PublicKey, signer.PublicKey) {
		t.Fatalf("selected root = %#v, want signer %s", selected, signer.KeyID)
	}

	for _, test := range []struct {
		name   string
		live   peeridentity.AccountRoot
		signer string
	}{
		{name: "unknown signer", live: peeridentity.AccountRoot{Keys: []peeridentity.AccountKey{extra}}, signer: signer.KeyID},
		{name: "missing signer", live: peeridentity.AccountRoot{Keys: []peeridentity.AccountKey{signer}}, signer: ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := selectAuthoritySignerRoot(test.live, Authority{SignerKeyID: test.signer}); !errors.Is(err, ErrRootSetChanged) {
				t.Fatalf("error = %v, want %v", err, ErrRootSetChanged)
			}
		})
	}
}
