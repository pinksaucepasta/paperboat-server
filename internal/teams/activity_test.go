package teams

import (
	"errors"
	"strings"
	"testing"
)

func TestActivityCursorBoundToTeam(t *testing.T) {
	cursor := activityCursor("team_a", 42)
	if n, err := parseActivityCursor("team_a", cursor); err != nil || n != 42 {
		t.Fatalf("cursor=%d err=%v", n, err)
	}
	for _, bad := range []string{cursor, "!", activityCursor("team_b", 0), strings.Repeat("x", 513)} {
		if _, err := parseActivityCursor("team_b", bad); !errors.Is(err, ErrInvalid) {
			t.Fatalf("accepted invalid cursor %q", bad)
		}
	}
}
func TestActivityMetadataSensitiveFieldsAndBounds(t *testing.T) {
	good := map[string]any{"target_account": "account_a", "active": true, "generation": uint64(4), "capabilities": []string{"files"}}
	if _, err := activityMetadata(good, true); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []map[string]any{
		{"terminal_contents": "private"}, {"filename": "private"}, {"env": "private"},
		{"role": strings.Repeat("x", 513)}, {"role": map[string]any{"secret": "private"}},
		{"capabilities": []any{"files", map[string]any{"secret": "private"}}},
	} {
		if _, err := activityMetadata(bad, true); !errors.Is(err, ErrInvalid) {
			t.Fatalf("unsafe metadata accepted: %v", err)
		}
	}
	projected, err := activityMetadata(map[string]any{"role": "viewer", "terminal_contents": "private"}, false)
	if err != nil || len(projected) != 1 || projected["role"] != "viewer" {
		t.Fatal("historical projection leaked or lost safe data")
	}
}
