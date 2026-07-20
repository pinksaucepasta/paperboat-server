package controlplane

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
)

var ErrUsageSignature = errors.New("usage report signature is invalid")

type signedUsageEnvelope struct {
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

type signedUsageKey struct {
	Node        string `json:"edge_node_id"`
	Epoch       string `json:"counter_epoch"`
	Environment string `json:"environment_id"`
	Route       string `json:"route_id"`
	Direction   string `json:"direction"`
	Revision    int64  `json:"route_revision"`
}

type signedUsageDocument struct {
	OperationID string         `json:"operation_id"`
	Key         signedUsageKey `json:"key"`
	Bytes       int64          `json:"bytes"`
	Start       time.Time      `json:"interval_start"`
	End         time.Time      `json:"interval_end"`
}

func (s *EdgeService) verifyUsage(ctx context.Context, request edgeUsageRequest) error {
	if len(request.Payload) == 0 || len(request.Payload) > maxEdgeDocument {
		return ErrUsageSignature
	}
	var envelope signedUsageEnvelope
	if strictUsageJSON(request.Payload, &envelope) != nil || envelope.Algorithm != "EdDSA" || envelope.KeyID == "" {
		return ErrUsageSignature
	}
	publicKey, err := s.store.Queries().GetActiveControlUsageVerificationKey(ctx, dbsqlc.GetActiveControlUsageVerificationKeyParams{KeyID: envelope.KeyID, EdgeNodeID: request.Node, Now: s.clock()})
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return ErrUsageSignature
	}
	return verifySignedUsageEnvelope(ed25519.PublicKey(publicKey), envelope, request)
}

func verifySignedUsageEnvelope(publicKey ed25519.PublicKey, envelope signedUsageEnvelope, request edgeUsageRequest) error {
	payload, err := base64.RawURLEncoding.DecodeString(envelope.Payload)
	if err != nil || len(payload) > maxEdgeDocument {
		return ErrUsageSignature
	}
	signature, err := base64.RawURLEncoding.DecodeString(envelope.Signature)
	if err != nil || !ed25519.Verify(publicKey, payload, signature) {
		return ErrUsageSignature
	}
	var document signedUsageDocument
	if strictUsageJSON(payload, &document) != nil || !sameSignedUsage(document, request) {
		return ErrUsageSignature
	}
	return nil
}

func sameSignedUsage(document signedUsageDocument, request edgeUsageRequest) bool {
	return document.OperationID == request.OperationID && document.Key.Node == request.Node &&
		document.Key.Epoch == request.Epoch && document.Key.Environment == request.Environment &&
		document.Key.Route == request.Route && document.Key.Revision == request.Revision &&
		document.Key.Direction == request.Direction && document.Bytes == request.Bytes &&
		document.Start.Equal(request.Start) && document.End.Equal(request.End)
}

func strictUsageJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrUsageSignature
	}
	return nil
}
