package controlplane

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/db/dbsqlc"
	"github.com/pinksaucepasta/paperboat-server/internal/mint"
)

var ErrHelperProof = errors.New("helper proof is invalid")

type helperProofEnvelope struct {
	Algorithm string `json:"alg"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

type HelperProofClaims struct {
	HelperID      string    `json:"helper_id"`
	EnvironmentID string    `json:"environment_id"`
	OperationID   string    `json:"operation_id"`
	Method        string    `json:"method"`
	Path          string    `json:"path"`
	BodySHA256    string    `json:"body_sha256"`
	IssuedAt      time.Time `json:"issued_at"`
	ExpiresAt     time.Time `json:"expires_at"`
}

func (s *EnrollmentService) VerifyHelperRequest(ctx context.Context, identityToken string, proof []byte, method, path string, body []byte) (HelperProofClaims, error) {
	if len(proof) == 0 || len(proof) > 16*1024 || len(body) > maxEdgeDocument {
		return HelperProofClaims{}, ErrHelperProof
	}
	now := s.clock().UTC()
	identity, err := s.signer.VerifyCredential(identityToken, s.issuer, "helper_identity", now)
	if err != nil || identity.HelperID == "" || identity.KeyThumbprint == "" {
		return HelperProofClaims{}, ErrHelperProof
	}
	helper, err := s.store.Queries().GetActiveControlHelper(ctx, dbsqlc.GetActiveControlHelperParams{ID: identity.HelperID, EnvironmentID: identity.EnvironmentID})
	if err != nil || !helper.KeyThumbprint.Valid || helper.KeyThumbprint.String != identity.KeyThumbprint || len(helper.PublicKey) != ed25519.PublicKeySize {
		return HelperProofClaims{}, ErrHelperProof
	}
	return verifyHelperProof(ed25519.PublicKey(helper.PublicKey), proof, identity.HelperID, identity.EnvironmentID, method, path, body, now)
}

func (s *EnrollmentService) VerifyEnrollmentCredential(token string) (mint.CredentialClaims, error) {
	if s.signer == nil {
		return mint.CredentialClaims{}, ErrEnrollmentInvalid
	}
	return s.signer.VerifyCredential(token, s.issuer, "helper_enrollment", s.clock().UTC())
}

func verifyHelperProof(publicKey ed25519.PublicKey, encoded []byte, helperID, environmentID, method, path string, body []byte, now time.Time) (HelperProofClaims, error) {
	var envelope helperProofEnvelope
	if strictProofJSON(encoded, &envelope) != nil || envelope.Algorithm != "EdDSA" {
		return HelperProofClaims{}, ErrHelperProof
	}
	payload, err := base64.RawURLEncoding.DecodeString(envelope.Payload)
	if err != nil || len(payload) > 16*1024 {
		return HelperProofClaims{}, ErrHelperProof
	}
	signature, err := base64.RawURLEncoding.DecodeString(envelope.Signature)
	if err != nil || !ed25519.Verify(publicKey, payload, signature) {
		return HelperProofClaims{}, ErrHelperProof
	}
	var claims HelperProofClaims
	if strictProofJSON(payload, &claims) != nil {
		return HelperProofClaims{}, ErrHelperProof
	}
	bodyHash := sha256.Sum256(body)
	if claims.HelperID != helperID || claims.EnvironmentID != environmentID || len(claims.OperationID) < 8 || len(claims.OperationID) > 128 || claims.Method != strings.ToUpper(method) || claims.Path != path || claims.BodySHA256 != base64.RawURLEncoding.EncodeToString(bodyHash[:]) || claims.IssuedAt.IsZero() || claims.ExpiresAt.IsZero() || !claims.ExpiresAt.After(claims.IssuedAt) || claims.ExpiresAt.Sub(claims.IssuedAt) > time.Minute || claims.IssuedAt.After(now.Add(time.Minute)) || !claims.ExpiresAt.After(now) {
		return HelperProofClaims{}, ErrHelperProof
	}
	return claims, nil
}

func strictProofJSON(data []byte, target any) error {
	if err := rejectDuplicateProofJSON(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrHelperProof
	}
	return nil
}

func rejectDuplicateProofJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, compound := token.(json.Delim)
		if !compound {
			return nil
		}
		switch delimiter {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return ErrHelperProof
				}
				if _, exists := seen[key]; exists {
					return ErrHelperProof
				}
				seen[key] = struct{}{}
				if err := walk(); err != nil {
					return err
				}
			}
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
		default:
			return ErrHelperProof
		}
		_, err = decoder.Token()
		return err
	}
	if err := walk(); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return ErrHelperProof
	}
	return nil
}
