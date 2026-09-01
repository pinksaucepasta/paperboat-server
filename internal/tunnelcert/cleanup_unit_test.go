package tunnelcert

import "testing"

func TestCertificateCleanupDisposition(t *testing.T) {
	tests := []struct {
		state         State
		action        string
		terminalState string
		ok            bool
	}{
		{state: StateSuperseded, action: "retire", terminalState: "retired", ok: true},
		{state: StateRevoked, action: "revoke", terminalState: "revoked", ok: true},
		{state: StateFailed, action: "revoke", terminalState: "revoked", ok: true},
		{state: StateActive, ok: false},
	}
	for _, test := range tests {
		got, ok := certificateCleanupDispositionFor(test.state)
		if ok != test.ok || got.action != test.action || got.terminalState != test.terminalState {
			t.Fatalf("state %q = %#v, %v; want %#v, %v", test.state, got, ok, certificateCleanupDisposition{action: test.action, terminalState: test.terminalState}, test.ok)
		}
	}
}
