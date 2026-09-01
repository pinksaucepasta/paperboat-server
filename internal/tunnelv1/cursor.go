package tunnelv1

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/previewtunnelapi"
)

type tunnelCursorCodec struct {
	key []byte
}

type tunnelCursorPayload struct {
	Version   int       `json:"version"`
	Kind      string    `json:"kind"`
	AccountID string    `json:"account_id"`
	CreatedAt time.Time `json:"created_at"`
	ID        string    `json:"id"`
}

const (
	maxTunnelCursorPayload = 512
	maxTunnelCursor        = 2048
)

func newTunnelCursorCodec(key []byte) (*tunnelCursorCodec, error) {
	if len(key) < 32 {
		return nil, errors.New("tunnel cursor signing key must contain at least 32 bytes")
	}
	return &tunnelCursorCodec{key: append([]byte(nil), key...)}, nil
}

func (c *tunnelCursorCodec) Encode(accountID string, position ListPosition) (string, error) {
	if accountID == "" || position.ID == "" || position.CreatedAt.IsZero() {
		return "", previewtunnelapi.ErrInvalidCursor
	}
	payload, err := json.Marshal(tunnelCursorPayload{
		Version: 1, Kind: "tunnel", AccountID: accountID, CreatedAt: position.CreatedAt.UTC(), ID: position.ID,
	})
	if err != nil || len(payload) > maxTunnelCursorPayload {
		return "", previewtunnelapi.ErrInvalidCursor
	}
	signature := c.sign(payload)
	encoded := base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(signature)
	if len(encoded) > maxTunnelCursor {
		return "", previewtunnelapi.ErrInvalidCursor
	}
	return encoded, nil
}

func (c *tunnelCursorCodec) Decode(raw, accountID string) (ListPosition, error) {
	if len(raw) == 0 || len(raw) > maxTunnelCursor {
		return ListPosition{}, previewtunnelapi.ErrInvalidCursor
	}
	parts := splitCursor(raw)
	if len(parts) != 2 {
		return ListPosition{}, previewtunnelapi.ErrInvalidCursor
	}
	encoding := base64.RawURLEncoding.Strict()
	payload, err := encoding.DecodeString(parts[0])
	if err != nil || len(payload) > maxTunnelCursorPayload {
		return ListPosition{}, previewtunnelapi.ErrInvalidCursor
	}
	signature, err := encoding.DecodeString(parts[1])
	if err != nil || len(signature) != sha256.Size || !hmac.Equal(signature, c.sign(payload)) {
		return ListPosition{}, previewtunnelapi.ErrInvalidCursor
	}
	var value tunnelCursorPayload
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil || decoder.Decode(&struct{}{}) != io.EOF || value.Version != 1 || value.Kind != "tunnel" || value.AccountID != accountID || value.ID == "" || value.CreatedAt.IsZero() {
		return ListPosition{}, previewtunnelapi.ErrInvalidCursor
	}
	return ListPosition{ID: value.ID, CreatedAt: value.CreatedAt.UTC()}, nil
}

func (c *tunnelCursorCodec) sign(payload []byte) []byte {
	mac := hmac.New(sha256.New, c.key)
	_, _ = mac.Write(payload)
	return mac.Sum(nil)
}

func splitCursor(raw string) []string {
	if raw == "" {
		return nil
	}
	// A cursor has exactly one separator. Reject additional separators rather
	// than silently accepting an ambiguous token.
	var first int = -1
	for i, r := range raw {
		if r == '.' {
			if first >= 0 {
				return nil
			}
			first = i
		}
	}
	if first <= 0 || first >= len(raw)-1 {
		return nil
	}
	return []string{raw[:first], raw[first+1:]}
}
