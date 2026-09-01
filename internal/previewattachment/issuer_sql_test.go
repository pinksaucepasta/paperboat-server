package previewattachment

import (
	"strings"
	"testing"
)

// The issuer passes a time.Time as the second query argument. Keep the
// timestamp cast in the SQL so PostgreSQL cannot infer the placeholder as an
// interval from the subtraction expression.
func TestPreviewCarrierIssuerSQLBindsClockAsTimestamp(t *testing.T) {
	for _, expression := range []string{
		"$2::timestamptz - interval '2 minutes'",
		"node.drain_deadline > $2::timestamptz",
	} {
		if !strings.Contains(getPreviewCarrierEdgeNodeSQL, expression) {
			t.Fatalf("issuer SQL is missing typed clock expression %q", expression)
		}
	}
}

func TestPreviewEdgeNodeSelectorSQLBindsClockAsTimestamp(t *testing.T) {
	for _, expression := range []string{
		"$1::timestamptz - interval '2 minutes'",
		"node.drain_deadline > $1::timestamptz",
	} {
		if !strings.Contains(selectPreviewEdgeNodeSQL, expression) {
			t.Fatalf("edge-node selector SQL is missing typed clock expression %q", expression)
		}
	}
}
