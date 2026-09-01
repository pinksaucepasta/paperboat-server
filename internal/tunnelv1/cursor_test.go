package tunnelv1

import (
	"bytes"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/previewtunnelapi"
)

func TestTunnelCursorBindsFamilyAndRejectsUnknownFields(t *testing.T) {
	codec, err := newTunnelCursorCodec(bytes.Repeat([]byte{4}, 32))
	if err != nil {
		t.Fatal(err)
	}
	position := ListPosition{CreatedAt: time.Date(2026, 8, 30, 10, 0, 0, 0, time.UTC), ID: "tun_1"}
	cursor, err := codec.Encode("acct_1", position)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := codec.Decode(cursor, "acct_1"); err != nil || got != position {
		t.Fatalf("round trip = %#v, %v", got, err)
	}

	for _, replacement := range []string{
		`{"version":1,"kind":"preview_lease","account_id":"acct_1","created_at":"2026-08-30T10:00:00Z","id":"tun_1"}`,
		`{"version":1,"kind":"tunnel","account_id":"acct_1","created_at":"2026-08-30T10:00:00Z","id":"tun_1","extra":true}`,
	} {
		forged := base64.RawURLEncoding.EncodeToString([]byte(replacement)) + "." + base64.RawURLEncoding.EncodeToString(codec.sign([]byte(replacement)))
		if _, err := codec.Decode(forged, "acct_1"); !errors.Is(err, previewtunnelapi.ErrInvalidCursor) {
			t.Errorf("forged cursor %q error = %v, want ErrInvalidCursor", replacement, err)
		}
	}
}
