package environment

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/peeridentity"
)

func TestSharedVectorInterop(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/contracts/environment-e2ee-v1/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		RootPublic         string            `json:"root_public"`
		Authority          string            `json:"authority"`
		AuthorityID        string            `json:"authority_id"`
		Manifest           string            `json:"manifest"`
		ManifestID         string            `json:"manifest_id"`
		SetManifest        string            `json:"set_manifest"`
		SetID              string            `json:"set_manifest_id"`
		Abort              string            `json:"abort"`
		AbortID            string            `json:"abort_id"`
		Expected           map[string]string `json:"expected_values"`
		HostRecipientKeyID string            `json:"host_recipient_key_id"`
	}
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	root, _ := base64.RawURLEncoding.DecodeString(vector.RootPublic)
	authorityRaw, _ := base64.RawURLEncoding.DecodeString(vector.Authority)
	manifestRaw, _ := base64.RawURLEncoding.DecodeString(vector.Manifest)
	rootID, _ := peeridentity.RootFingerprint(ed25519.PublicKey(root))
	authority, err := ParseAuthority(authorityRaw, peeridentity.AccountRoot{Keys: []peeridentity.AccountKey{{KeyID: "aek_" + rootID, PublicKey: ed25519.PublicKey(root)}}})
	if err != nil {
		t.Fatalf("authority: %v", err)
	}
	if authority.ID != vector.AuthorityID {
		t.Fatalf("authority id=%s", authority.ID)
	}
	if authority.SignerKeyID != "aek_"+rootID {
		t.Fatalf("authority signer=%s, want aek_%s", authority.SignerKeyID, rootID)
	}
	manifest, err := ParseManifest(manifestRaw, authority)
	if err != nil {
		t.Fatalf("manifest: %v", err)
	}
	if manifest.ID != vector.ManifestID {
		t.Fatalf("manifest id=%s", manifest.ID)
	}
	setRaw, _ := base64.RawURLEncoding.DecodeString(vector.SetManifest)
	setManifest, err := ParseManifest(setRaw, authority)
	if err != nil || setManifest.ID != vector.SetID || len(setManifest.Names) == 0 {
		t.Fatalf("set manifest: id=%q names=%v err=%v", setManifest.ID, setManifest.Names, err)
	}
	canary := []byte(vector.Expected["APP_TOKEN"])
	requestBody, _ := json.Marshal(map[string]any{"schema": "paperboat.environment-manifest-mutation/v1", "expected_version": 1, "operation_id": setManifest.OperationID, "envelope": vector.SetManifest})
	databaseRepresentation := bytes.Join([][]byte{setRaw, []byte(setManifest.ID), []byte(setManifest.AuthorityID), []byte(setManifest.OperationID), []byte(setManifest.Names[0])}, nil)
	auditRepresentation, _ := json.Marshal(map[string]any{"scope": setManifest.Scope, "changed_names": setManifest.ChangedNames, "version": setManifest.Version, "key_epoch": setManifest.KeyEpoch, "manifest_id": setManifest.ID})
	observationRepresentation, _ := json.Marshal(Observation{Schema: ObservationSchema, ObservationSeq: 1, HostRecipientKeyID: vector.HostRecipientKeyID, Authority: &AuthorityRef{Generation: int64(authority.Generation), AuthorityID: authority.ID}, State: "pending", ObservedAt: time.Unix(1, 0).UTC()})
	runtimeRepresentation, _ := json.Marshal(Bundle{Schema: BundleSchema, AuthorityHead: AuthorityRef{Generation: int64(authority.Generation), AuthorityID: authority.ID}, AuthorityDocuments: []string{}, GlobalManifest: &BundleManifest{Version: int64(setManifest.Version), KeyEpoch: int64(setManifest.KeyEpoch), ManifestID: setManifest.ID, Envelope: vector.SetManifest}})
	for _, surface := range [][]byte{requestBody, databaseRepresentation, auditRepresentation, observationRepresentation, runtimeRepresentation, []byte(ErrProtocolInvalid.Error())} {
		if len(canary) == 0 || bytes.Contains(surface, canary) {
			t.Fatal("plaintext canary crossed a server-side ENV surface")
		}
	}
	abortRaw, _ := base64.RawURLEncoding.DecodeString(vector.Abort)
	abort, err := ParseAbort(abortRaw, peeridentity.AccountRoot{Keys: []peeridentity.AccountKey{{KeyID: "aek_" + rootID, PublicKey: ed25519.PublicKey(root)}}})
	if err != nil || DocumentID(abort.Raw) != vector.AbortID {
		t.Fatalf("abort: id=%q err=%v", DocumentID(abort.Raw), err)
	}
}
