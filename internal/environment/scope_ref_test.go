package environment

import "testing"

func TestScopeRefKeyIsTypedAndUnambiguous(t *testing.T) {
	tests := []struct {
		name    string
		ref     ScopeRef
		wantKey string
		want    string
	}{
		{name: "global", ref: ScopeRef{Scope: ScopeGlobal}, wantKey: "g", want: ScopeGlobal},
		{name: "machine-global", ref: ScopeRef{Scope: ScopeMachine, MachineID: "global"}, wantKey: "m:global", want: "global"},
		{name: "machine-id", ref: ScopeRef{Scope: ScopeMachine, MachineID: "machine_01"}, wantKey: "m:machine_01", want: "machine_01"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := test.ref.Key(); got != test.wantKey {
				t.Fatalf("ScopeRef.Key()=%q, want %q", got, test.wantKey)
			}
			scope, machine := parseScopeKey(test.wantKey)
			if scope == ScopeGlobal {
				if machine != "" {
					t.Fatalf("global machine id=%q, want empty", machine)
				}
			} else if scope != ScopeMachine || machine != test.want {
				t.Fatalf("parseScopeKey(%q)=(%q,%q), want (%q,%q)", test.wantKey, scope, machine, ScopeMachine, test.want)
			}
		})
	}

	if global, machine := parseScopeKey((ScopeRef{Scope: ScopeGlobal}).Key()); global == ScopeMachine || machine != "" {
		t.Fatalf("global key parsed as (%q,%q)", global, machine)
	}
	if global, machine := parseScopeKey((ScopeRef{Scope: ScopeMachine, MachineID: "global"}).Key()); global != ScopeMachine || machine != "global" {
		t.Fatalf("machine key parsed as (%q,%q)", global, machine)
	}
}

func TestParseScopeKeyRejectsUntypedOrMalformedKeys(t *testing.T) {
	for _, key := range []string{"global", "machine_01", "m:", "m:bad:id", "x:global", ""} {
		scope, machine := parseScopeKey(key)
		if scope != "" || machine != "" {
			t.Errorf("parseScopeKey(%q)=(%q,%q), want empty scope and machine", key, scope, machine)
		}
	}
}
