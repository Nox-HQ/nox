package core

import "testing"

func TestScopeOfRuleAndOnlyScopes(t *testing.T) {
	for id, want := range map[string]Scope{
		"VULN-001": ScopeDeps, "IAC-018": ScopeIaC, "TAINT-AI-001": ScopeCode, "SEC-100": ScopeSecrets,
	} {
		if got, ok := ScopeOfRule(id); !ok || got != want {
			t.Errorf("ScopeOfRule(%s) = %q, %v; want %q", id, got, ok, want)
		}
	}
	if _, ok := ScopeOfRule("ORG-001"); ok {
		t.Error("a custom rule was assigned a scope")
	}
	only := OnlyScopes(ScopeIaC)
	if !only.Has(ScopeIaC) || only.Has(ScopeDeps) || only.Full() {
		t.Errorf("OnlyScopes(iac) = %+v", only)
	}
}
