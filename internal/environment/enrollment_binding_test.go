package environment

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"slices"
	"testing"
	"time"
)

func testEnrollmentBinding(t *testing.T, subjectKind int) (enrollmentRow, Binding, EnrollmentCanonicalInput) {
	t.Helper()
	input := EnrollmentCanonicalInput{
		AccountID:           "acct_enrollment",
		OperationID:         "envop_0102030405060708090a0b0c0d0e0f10",
		SubjectKind:         subjectKind,
		SubjectID:           "subject_enrollment",
		SubjectGeneration:   3,
		KeyGeneration:       4,
		EndpointCertificate: []byte("endpoint-certificate"),
		SigningPublic:       []byte("01234567890123456789012345678901"),
		RecipientPublic:     []byte("abcdefghijklmnopqrstuvwxyz123456"),
		ExpiresAt:           time.Unix(1_700_000_000, 0).UTC(),
	}
	if subjectKind == 2 {
		input.EndpointCertificate = nil
	}
	if subjectKind == 3 {
		input.SigningPublic = nil
	}
	if len(input.SigningPublic) > 0 {
		input.SigningKeyID = validKeyIDForTest(t, "sigk_", input.SigningPublic)
	}
	input.RecipientKeyID = validKeyIDForTest(t, "envk_", input.RecipientPublic)

	canonical, digest, _, err := CanonicalEnrollment(input)
	if err != nil {
		t.Fatalf("canonical enrollment: %v", err)
	}
	row := enrollmentRow{
		Canonical:     canonical,
		RequestDigest: digest[:],
		OperationID:   input.OperationID,
	}
	binding := Binding{
		AccountID:           input.AccountID,
		SubjectKind:         input.SubjectKind,
		SubjectID:           input.SubjectID,
		SubjectGeneration:   input.SubjectGeneration,
		KeyGeneration:       input.KeyGeneration,
		EndpointCertificate: slices.Clone(input.EndpointCertificate),
		SigningPublicKey:    ed25519.PublicKey(slices.Clone(input.SigningPublic)),
		SigningKeyID:        input.SigningKeyID,
		RecipientKeyID:      input.RecipientKeyID,
		NotAfter:            nil,
		signingKeyIDPresent: input.SigningKeyID != "",
	}
	copy(binding.RecipientPublicKey[:], input.RecipientPublic)
	return row, binding, input
}

func validKeyIDForTest(t *testing.T, prefix string, public []byte) string {
	t.Helper()
	crv := "X25519"
	if prefix == "sigk_" {
		crv = "Ed25519"
	}
	jwk := []byte(`{"crv":"` + crv + `","kty":"OKP","x":"` + base64.RawURLEncoding.EncodeToString(public) + `"}`)
	digest := sha256.Sum256(jwk)
	return prefix + base64.RawURLEncoding.EncodeToString(digest[:])
}

func TestBindingMatchesEnrollmentRejectsPublicFieldSubstitution(t *testing.T) {
	row, binding, input := testEnrollmentBinding(t, 1)
	tests := []struct {
		name   string
		mutate func(*Binding)
	}{
		{name: "endpoint certificate", mutate: func(value *Binding) { value.EndpointCertificate = []byte("attacker-endpoint") }},
		{name: "signing public key", mutate: func(value *Binding) {
			value.SigningPublicKey = ed25519.PublicKey([]byte("attacker-signing-key-012345678901"))
		}},
		{name: "signing key id", mutate: func(value *Binding) {
			value.SigningKeyID = validKeyIDForTest(t, "sigk_", []byte("attacker-signing-key-012345678901"))
		}},
		{name: "subject", mutate: func(value *Binding) { value.SubjectID = "attacker-subject" }},
		{name: "subject generation", mutate: func(value *Binding) { value.SubjectGeneration++ }},
		{name: "key generation", mutate: func(value *Binding) { value.KeyGeneration++ }},
		{name: "recipient public key", mutate: func(value *Binding) { value.RecipientPublicKey[0] ^= 0xff }},
		{name: "recipient key id", mutate: func(value *Binding) { value.RecipientKeyID = input.RecipientKeyID[:len(input.RecipientKeyID)-1] + "A" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := binding
			test.mutate(&candidate)
			if bindingMatchesEnrollment(candidate, row) {
				t.Fatalf("accepted substituted %s", test.name)
			}
		})
	}
}

func TestBindingMatchesEnrollmentRequiresExactNullSemantics(t *testing.T) {
	t.Run("browser endpoint null", func(t *testing.T) {
		row, binding, _ := testEnrollmentBinding(t, 2)
		binding.EndpointCertificate = []byte{}
		if bindingMatchesEnrollment(binding, row) {
			t.Fatal("accepted empty endpoint bytes in place of null")
		}
	})
	t.Run("host signer null", func(t *testing.T) {
		row, binding, _ := testEnrollmentBinding(t, 3)
		binding.SigningPublicKey = ed25519.PublicKey([]byte{})
		binding.signingKeyIDPresent = true
		if bindingMatchesEnrollment(binding, row) {
			t.Fatal("accepted empty signer bytes in place of null")
		}
	})
	t.Run("host signer id null", func(t *testing.T) {
		row, binding, _ := testEnrollmentBinding(t, 3)
		binding.signingKeyIDPresent = true
		if bindingMatchesEnrollment(binding, row) {
			t.Fatal("accepted empty signer id in place of null")
		}
	})
}
