package previewattachment

import (
	"strings"
	"testing"
)

func TestClaimPreviewCarrierOutboxUsesTimestampRetryDeadline(t *testing.T) {
	const expected = "next_attempt_at = $6::timestamptz + interval '30 seconds'"
	if !strings.Contains(claimPreviewCarrierOutboxSQL, expected) {
		t.Fatalf("claim query does not cast retry base to timestamptz: %q", claimPreviewCarrierOutboxSQL)
	}
	if strings.Contains(claimPreviewCarrierOutboxSQL, "next_attempt_at = $6 + interval") {
		t.Fatal("claim query leaves retry base parameter untyped")
	}
	if !strings.Contains(claimPreviewCarrierOutboxSQL, "updated_at = $6::timestamptz") {
		t.Fatal("claim query does not cast updated_at parameter to timestamptz")
	}
}
