// Package naming owns memorable, low-key public names across Paperboat.
package naming

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

var qualities = []string{
	"agile", "alert", "bold", "brisk", "bright", "calm", "certain", "classic",
	"clear", "clever", "cool", "crisp", "direct", "eager", "easy", "even",
	"fair", "fine", "fluent", "free", "fresh", "gentle", "graceful", "grand",
	"happy", "hardy", "honest", "keen", "kind", "light", "lively", "lucid",
	"nimble", "open", "patient", "quiet", "ready", "serene", "simple", "smooth",
	"sound", "stable", "steady", "subtle", "swift", "trusted", "vivid", "warm",
}

var atmospheres = []string{
	"alpine", "amber", "autumn", "azure", "blooming", "blue", "cloudless", "coastal",
	"coral", "dawn", "dusky", "evening", "forest", "glacial", "golden", "green",
	"indigo", "island", "ivory", "jade", "lunar", "marine", "meadow", "midnight",
	"misty", "morning", "northern", "ocean", "pearl", "polar", "radiant", "river",
	"rosy", "shaded", "silver", "solar", "spring", "starlit", "summer", "sunlit",
	"tidal", "tranquil", "verdant", "violet", "wild", "windswept", "winter", "woodland",
}

var waypoints = []string{
	"anchor", "bay", "beacon", "bridge", "cape", "channel", "coast", "compass",
	"cove", "creek", "current", "deck", "delta", "dock", "ferry", "harbor",
	"haven", "helm", "horizon", "inlet", "island", "journey", "lagoon", "lantern",
	"map", "marina", "mast", "ocean", "passage", "pier", "port", "quay",
	"reef", "river", "route", "sail", "shore", "signal", "star", "strait",
	"summit", "tide", "trail", "vessel", "voyage", "wake", "waypoint", "wharf",
}

// Session returns a deterministic three-word name for a positive environment-local ordinal.
func Session(ordinal int32) string {
	if ordinal < 1 {
		ordinal = 1
	}
	poolSize := len(qualities) * len(atmospheres) * len(waypoints)
	// 7919 is coprime with the 48^3 pool, so this spreads adjacent ordinals
	// across the vocabulary without introducing collisions within one cycle.
	index := (int(ordinal-1) * 7919) % poolSize
	return qualities[(index/(len(atmospheres)*len(waypoints)))%len(qualities)] + "-" +
		atmospheres[(index/len(waypoints))%len(atmospheres)] + "-" +
		waypoints[index%len(waypoints)]
}

// PublicSlug returns a stable three-word label and four-digit suffix for an opaque identity.
func PublicSlug(identity string) string {
	digest := sha256.Sum256([]byte("paperboat-preview:" + identity))
	quality := qualities[int(binary.BigEndian.Uint16(digest[0:2]))%len(qualities)]
	atmosphere := atmospheres[int(binary.BigEndian.Uint16(digest[2:4]))%len(atmospheres)]
	waypoint := waypoints[int(binary.BigEndian.Uint16(digest[4:6]))%len(waypoints)]
	digits := binary.BigEndian.Uint16(digest[6:8]) % 10000
	return fmt.Sprintf("%s-%s-%s-%04d", quality, atmosphere, waypoint, digits)
}
