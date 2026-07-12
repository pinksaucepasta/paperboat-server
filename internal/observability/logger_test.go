package observability

import "testing"

func TestNormalizeRequestID(t *testing.T) {
	for _, valid := range []string{"req_123", "trace:abc.def-1"} {
		if got := NormalizeRequestID(valid); got != valid {
			t.Fatalf("NormalizeRequestID(%q) = %q", valid, got)
		}
	}
	for _, invalid := range []string{"space value", "path/value", "line\nbreak", string(make([]byte, 201))} {
		if got := NormalizeRequestID(invalid); got != "" {
			t.Fatalf("NormalizeRequestID(%q) = %q", invalid, got)
		}
	}
}
