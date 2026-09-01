//go:build trk35_release_candidate

package releases

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestTRK35ExternalBundleReady is the server-side half of the local release
// candidate gate. The companion script creates the bundle from the real
// publisher output and passes its absolute path through the environment.
//
// TUF authenticity is enforced before this health check by the publisher's
// verify-published step and by the SHA-256 authenticated bundle handoff. Ready
// intentionally remains a shape/integrity gate for the origin; release clients
// are the trust boundary that verify TUF signatures before consuming targets.
func TestTRK35ExternalBundleReady(t *testing.T) {
	directory := strings.TrimSpace(os.Getenv("PAPERBOAT_TRK35_RELEASE_BUNDLE"))
	if directory == "" {
		t.Skip("PAPERBOAT_TRK35_RELEASE_BUNDLE is not set")
	}
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		t.Fatal("PAPERBOAT_TRK35_RELEASE_BUNDLE must be an absolute clean directory")
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("invalid release bundle directory %q: %v", directory, err)
	}

	current, err := ReadCurrent(directory)
	if err != nil {
		t.Fatalf("read publisher-generated current.json: %v", err)
	}
	if expected := strings.TrimSpace(os.Getenv("PAPERBOAT_TRK35_RELEASE_VERSION")); expected != "" && current.Version != expected {
		t.Fatalf("bundle version=%q, want %q", current.Version, expected)
	}
	if err := Ready(directory); err != nil {
		t.Fatalf("server Ready rejected publisher-generated bundle: %v", err)
	}

	// Keep the assertion tied to the public contract rather than merely
	// accepting a future fixture with an arbitrary number of assets.
	if len(current.Assets) != len(supportedPlatformArchitectures) {
		t.Fatalf("bundle assets=%d, want %d", len(current.Assets), len(supportedPlatformArchitectures))
	}
	if _, err := os.Lstat(filepath.Join(directory, "tuf", "targets")); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("inspect TUF target directory: %v", err)
	}
}
