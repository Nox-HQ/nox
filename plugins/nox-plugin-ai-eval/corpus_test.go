package main

import "testing"

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}

func TestOWASPTags(t *testing.T) {
	cases := []struct {
		name string
		kind AttackKind
		want []string
	}{
		{"jailbreak", AttackJailbreak, []string{"owasp-llm01", "owasp-asi01"}},
		{"role_confusion", AttackRoleConfusion, []string{"owasp-llm01", "owasp-asi01"}},
		{"system_leak", AttackSystemLeak, []string{"owasp-llm07"}},
		{"tool_misuse", AttackToolMisuse, []string{"owasp-asi02", "owasp-llm06"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := owaspTags(tc.kind)
			if len(got) != len(tc.want) {
				t.Fatalf("kind %s: got %v, want %v", tc.kind, got, tc.want)
			}
			for _, w := range tc.want {
				if !contains(got, w) {
					t.Errorf("kind %s: missing tag %q (got %v)", tc.kind, w, got)
				}
			}
		})
	}

	// Unknown / zero kind must never guess a mapping.
	if got := owaspTags(AttackKind("")); got != nil {
		t.Errorf("zero kind: expected nil, got %v", got)
	}
	if got := owaspTags(AttackKind("nonsense")); got != nil {
		t.Errorf("unknown kind: expected nil, got %v", got)
	}
}

func TestOWASPTags_EveryCorpusKindMapped(t *testing.T) {
	// Every kind used by the shipped corpus must carry OWASP tags so no
	// emitted finding lacks a control mapping.
	for _, e := range Corpus() {
		if len(owaspTags(e.Kind)) == 0 {
			t.Errorf("corpus entry %s (kind %s) has no OWASP mapping", e.ID, e.Kind)
		}
	}
}

func TestCorpus_Nonempty(t *testing.T) {
	c := Corpus()
	if len(c) < 10 {
		t.Errorf("corpus too small (got %d)", len(c))
	}
}

func TestCorpus_AllEntriesHaveMarkers(t *testing.T) {
	for _, e := range Corpus() {
		if e.ID == "" {
			t.Errorf("entry has empty ID")
		}
		if e.Prompt == "" {
			t.Errorf("entry %s has empty prompt", e.ID)
		}
		if len(e.Markers) == 0 {
			t.Errorf("entry %s has no markers", e.ID)
		}
	}
}

func TestMatchAny_HitsCaseInsensitive(t *testing.T) {
	if marker, ok := MatchAny("DAN ready to roll", []string{"dan ready"}); !ok || marker != "dan ready" {
		t.Errorf("expected case-insensitive hit, got marker=%q ok=%v", marker, ok)
	}
}

func TestMatchAny_NoFalseHit(t *testing.T) {
	if _, ok := MatchAny("response with no jailbreak markers", []string{"dan ready", "pwned"}); ok {
		t.Error("expected no hit on benign response")
	}
}

func TestCorpus_KindsCovered(t *testing.T) {
	want := map[AttackKind]bool{
		AttackJailbreak:     false,
		AttackSystemLeak:    false,
		AttackRoleConfusion: false,
		AttackToolMisuse:    false,
	}
	for _, e := range Corpus() {
		if _, ok := want[e.Kind]; ok {
			want[e.Kind] = true
		}
	}
	for k, hit := range want {
		if !hit {
			t.Errorf("corpus missing entries for kind %s", k)
		}
	}
}
