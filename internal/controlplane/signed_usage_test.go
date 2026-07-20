package controlplane

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestVerifySignedUsageEnvelope(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Unix(1, 0).UTC()
	request := edgeUsageRequest{OperationID: "op_signed_01", Node: "node_1", Epoch: "epoch_1", Environment: "env_1", Route: "route_1", Revision: 2, Direction: "egress", Bytes: 42, Start: start, End: start.Add(time.Second)}
	document := signedUsageDocument{OperationID: request.OperationID, Key: signedUsageKey{Node: request.Node, Epoch: request.Epoch, Environment: request.Environment, Route: request.Route, Direction: request.Direction, Revision: request.Revision}, Bytes: request.Bytes, Start: request.Start, End: request.End}
	payload, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	envelope := signedUsageEnvelope{Algorithm: "EdDSA", KeyID: "usage-key-1", Payload: base64.RawURLEncoding.EncodeToString(payload), Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, payload))}
	if err := verifySignedUsageEnvelope(publicKey, envelope, request); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}

	tampered := request
	tampered.Bytes++
	if err := verifySignedUsageEnvelope(publicKey, envelope, tampered); !errors.Is(err, ErrUsageSignature) {
		t.Fatalf("relabeled report error = %v", err)
	}
	envelope.Signature = base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	if err := verifySignedUsageEnvelope(publicKey, envelope, request); !errors.Is(err, ErrUsageSignature) {
		t.Fatalf("tampered signature error = %v", err)
	}
}

func TestVerifySignedUsageEnvelopeRejectsUnknownFields(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"operation_id":"op","key":{},"bytes":0,"interval_start":"2026-01-01T00:00:00Z","interval_end":"2026-01-01T00:00:00Z","unknown":true}`)
	envelope := signedUsageEnvelope{Algorithm: "EdDSA", KeyID: "key", Payload: base64.RawURLEncoding.EncodeToString(payload), Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, payload))}
	if err := verifySignedUsageEnvelope(publicKey, envelope, edgeUsageRequest{}); !errors.Is(err, ErrUsageSignature) {
		t.Fatalf("unknown field error = %v", err)
	}
}
