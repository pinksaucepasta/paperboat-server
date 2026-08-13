package machinealias

import "testing"

func TestCandidateProducesStableDNSLabels(t *testing.T) {
	tests := map[string]string{
		"Studio Mac":   "studio-mac",
		"  API  ":      "api-machine",
		"東京":           "paperboat-machine",
		"Build___Host": "build-host",
	}
	for input, expected := range tests {
		if got := Candidate(input, 1); got != expected || !Valid(got) {
			t.Fatalf("Candidate(%q)=%q expected=%q", input, got, expected)
		}
	}
	if got := Candidate(stringsRepeat("a", 70), 12); len(got) != 63 || got[len(got)-3:] != "-12" || !Valid(got) {
		t.Fatalf("bounded candidate=%q", got)
	}
}

func stringsRepeat(value string, count int) string {
	result := ""
	for range count {
		result += value
	}
	return result
}
