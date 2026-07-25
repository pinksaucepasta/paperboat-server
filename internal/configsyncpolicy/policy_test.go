package configsyncpolicy

import (
	"slices"
	"testing"
)

func TestMandatoryExcludesProtectPaperboatRuntime(t *testing.T) {
	for _, required := range []string{
		".config/paperboat",
		".config/paperboat/**",
		".local/bin/pbh",
		".config/systemd/user/paperboat-helper.service",
		".config/systemd/user/default.target.wants/paperboat-helper.service",
		"Library/LaunchAgents/com.pinksaucepasta.paperboat-helper.plist",
	} {
		if !slices.Contains(MandatoryExcludes(), required) {
			t.Fatalf("missing Paperboat runtime exclusion %q", required)
		}
	}
}
