package naming

import (
	"strings"
	"testing"
)

func TestSessionNamesAreStableDistinctAndReserved(t *testing.T) {
	seen := map[string]bool{}
	poolSize := int32(len(qualities) * len(atmospheres) * len(waypoints))
	for ordinal := int32(1); ordinal <= poolSize; ordinal++ {
		name := Session(ordinal)
		if seen[name] {
			t.Fatalf("ordinal %d generated invalid or duplicate name %q", ordinal, name)
		}
		seen[name] = true
	}
	if Session(1) != Session(1) || len(strings.Split(Session(1), "-")) != 3 {
		t.Fatalf("unexpected naming contract: first=%q", Session(1))
	}
}

func TestPublicSlugIsReadableStableAndHasFourDigitSuffix(t *testing.T) {
	identity := "p-abcdefghijklmnopqrstuvwxyz"
	slug := PublicSlug(identity)
	parts := strings.Split(slug, "-")
	if slug != PublicSlug(identity) || len(parts) != 4 || len(parts[3]) != 4 {
		t.Fatalf("public slug = %q", slug)
	}
	for _, r := range parts[3] {
		if r < '0' || r > '9' {
			t.Fatalf("public slug suffix is not numeric: %q", slug)
		}
	}
}
