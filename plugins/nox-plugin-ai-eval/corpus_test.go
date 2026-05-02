package main

import "testing"

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
