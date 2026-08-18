package releaseauthority

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
	"time"
)

func TestVerifyRequiresConfiguredThresholdAndCanonicalPayload(t *testing.T) {
	keys := make([]Key, 3)
	private := make([]ed25519.PrivateKey, 3)
	for i := range keys {
		public, secret, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		keys[i] = Key{ID: string(rune('a' + i)), Public: public}
		private[i] = secret
	}
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	service := &Service{keys: map[string]ed25519.PublicKey{"a": keys[0].Public, "b": keys[1].Public, "c": keys[2].Public}, threshold: 2, now: func() time.Time { return now }}
	bundle := Bundle{Schema: SchemaV1, ReleaseID: "rel_2026.08.18.1", Version: "2026.08.18.1", Platform: "linux", Architecture: "amd64", Action: "promote", PolicyRevision: 2, RolloutPercentage: 5, TUFIndexTarget: "release-index-stable-linux-amd64.json", TUFIndexSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", AuthorityRequestID: "rar_0123456789abcdef", IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)}
	payload, err := canonical(bundle)
	if err != nil {
		t.Fatal(err)
	}
	message := append([]byte("paperboat.release-authority.v1\x00"), payload...)
	bundle.Signatures = []Signature{{KeyID: "a", Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(private[0], message))}, {KeyID: "b", Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(private[1], message))}}
	if err := service.Verify(bundle); err != nil {
		t.Fatal(err)
	}
	bundle.Signatures = bundle.Signatures[:1]
	if err := service.Verify(bundle); !errors.Is(err, ErrSignature) {
		t.Fatalf("error=%v", err)
	}
}

func TestDecodeRejectsDuplicateAndUnknownFields(t *testing.T) {
	if _, err := Decode([]byte(`{"schema":"x","schema":"y"}`)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("duplicate error=%v", err)
	}
	if _, err := Decode([]byte(`{"unknown":true}`)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown error=%v", err)
	}
}
