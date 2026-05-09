package assist

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNewTriageHistory_Defaults(t *testing.T) {
	h := NewTriageHistory("/tmp/x.json")
	if h.SchemaVersion != HistorySchemaVersion {
		t.Errorf("expected schema %s, got %s", HistorySchemaVersion, h.SchemaVersion)
	}
	if h.Path() != "/tmp/x.json" {
		t.Errorf("Path() = %s", h.Path())
	}
	if len(h.Decisions) != 0 {
		t.Errorf("expected 0 decisions, got %d", len(h.Decisions))
	}
}

func TestLoadTriageHistory_MissingFileIsEmpty(t *testing.T) {
	dir := t.TempDir()
	h, err := LoadTriageHistory(filepath.Join(dir, "nonexistent.json"))
	if err != nil {
		t.Fatalf("Load on missing file should not error, got %v", err)
	}
	if len(h.Decisions) != 0 {
		t.Errorf("expected empty history, got %d", len(h.Decisions))
	}
}

func TestLoadTriageHistory_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "th.json")

	h := NewTriageHistory(path)
	h.Add(TriageDecision{
		Fingerprint:      "fp-1",
		ContextHash:      HashContext("db.Query(x + y)"),
		RuleID:           "SEC-002",
		Verdict:          "true_positive",
		AdjustedSeverity: "high",
		Rationale:        "Concatenated SQL with userID",
		DecidedBy:        "alice@example",
	})
	if err := h.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := LoadTriageHistory(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(got.Decisions) != 1 {
		t.Fatalf("expected 1 decision, got %d", len(got.Decisions))
	}
	if got.Decisions[0].Fingerprint != "fp-1" {
		t.Errorf("fingerprint mismatch: %s", got.Decisions[0].Fingerprint)
	}
}

func TestAdd_ReplacesExistingByFingerprintAndContext(t *testing.T) {
	h := NewTriageHistory("/tmp/x.json")
	ctxHash := HashContext("snippet")
	h.Add(TriageDecision{Fingerprint: "fp", ContextHash: ctxHash, Verdict: "needs_review"})
	h.Add(TriageDecision{Fingerprint: "fp", ContextHash: ctxHash, Verdict: "false_positive"})
	if len(h.Decisions) != 1 {
		t.Fatalf("expected dedup, got %d decisions", len(h.Decisions))
	}
	if h.Decisions[0].Verdict != "false_positive" {
		t.Errorf("expected latest verdict, got %s", h.Decisions[0].Verdict)
	}
}

func TestLookup_ReturnsMostRecent(t *testing.T) {
	h := NewTriageHistory("/tmp/x.json")
	ctxHash := HashContext("snippet")
	h.Add(TriageDecision{Fingerprint: "fp", ContextHash: ctxHash, Verdict: "needs_review"})

	got, ok := h.Lookup("fp", ctxHash)
	if !ok {
		t.Fatalf("Lookup miss")
	}
	if got.Verdict != "needs_review" {
		t.Errorf("verdict = %s", got.Verdict)
	}

	if _, ok := h.Lookup("missing", ctxHash); ok {
		t.Errorf("expected lookup miss for unknown fingerprint")
	}
}

func TestSimilar_ByRuleID_OrderedByRecency(t *testing.T) {
	h := NewTriageHistory("/tmp/x.json")
	now := time.Now()
	h.Add(TriageDecision{Fingerprint: "a", RuleID: "SEC-002", DecidedAt: now.Add(-3 * time.Hour)})
	h.Add(TriageDecision{Fingerprint: "b", RuleID: "SEC-002", DecidedAt: now.Add(-1 * time.Hour)})
	h.Add(TriageDecision{Fingerprint: "c", RuleID: "SEC-001", DecidedAt: now})

	got := h.Similar("SEC-002", 5)
	if len(got) != 2 {
		t.Fatalf("expected 2 SEC-002 matches, got %d", len(got))
	}
	if got[0].Fingerprint != "b" {
		t.Errorf("expected most recent first; got %s", got[0].Fingerprint)
	}

	if h.Similar("SEC-002", 0) != nil {
		t.Errorf("maxN=0 should return nil")
	}
}

func TestExport_StableOrdering(t *testing.T) {
	h := NewTriageHistory("/tmp/x.json")
	now := time.Now()
	h.Add(TriageDecision{Fingerprint: "z", RuleID: "SEC-002", DecidedAt: now})
	h.Add(TriageDecision{Fingerprint: "a", RuleID: "SEC-001", DecidedAt: now.Add(time.Hour)})
	h.Add(TriageDecision{Fingerprint: "b", RuleID: "SEC-001", DecidedAt: now})

	dest := filepath.Join(t.TempDir(), "export.json")
	if err := h.Export(dest); err != nil {
		t.Fatalf("Export: %v", err)
	}
	raw, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read export: %v", err)
	}
	var exported TriageHistory
	if err := json.Unmarshal(raw, &exported); err != nil {
		t.Fatalf("unmarshal export: %v", err)
	}
	rules := []string{}
	for _, d := range exported.Decisions {
		rules = append(rules, d.RuleID)
	}
	want := []string{"SEC-001", "SEC-001", "SEC-002"}
	for i := range want {
		if rules[i] != want[i] {
			t.Errorf("rules[%d]=%s want %s; full=%v", i, rules[i], want[i], rules)
		}
	}
}

func TestImport_PrefersNewerByDecidedAt(t *testing.T) {
	dir := t.TempDir()
	older := time.Now().Add(-2 * time.Hour).UTC()
	newer := time.Now().UTC()

	src := filepath.Join(dir, "src.json")
	imp := TriageHistory{
		SchemaVersion: HistorySchemaVersion,
		Decisions: []TriageDecision{
			{Fingerprint: "fp", ContextHash: "ctx", RuleID: "SEC-002", Verdict: "false_positive", DecidedAt: newer},
			{Fingerprint: "new", ContextHash: "ctx2", RuleID: "SEC-001", Verdict: "true_positive", DecidedAt: newer},
		},
	}
	body, _ := json.Marshal(&imp)
	if err := os.WriteFile(src, body, 0o644); err != nil {
		t.Fatalf("write src: %v", err)
	}

	h := NewTriageHistory(filepath.Join(dir, "local.json"))
	h.Add(TriageDecision{Fingerprint: "fp", ContextHash: "ctx", RuleID: "SEC-002", Verdict: "true_positive", DecidedAt: older})

	changed, err := h.Import(src)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if changed != 2 {
		t.Errorf("expected 2 changed, got %d", changed)
	}
	got, _ := h.Lookup("fp", "ctx")
	if got.Verdict != "false_positive" {
		t.Errorf("expected newer false_positive to win, got %s", got.Verdict)
	}
}

func TestImport_OlderDoesNotOverwrite(t *testing.T) {
	dir := t.TempDir()
	older := time.Now().Add(-2 * time.Hour).UTC()
	newer := time.Now().UTC()

	src := filepath.Join(dir, "src.json")
	imp := TriageHistory{
		SchemaVersion: HistorySchemaVersion,
		Decisions: []TriageDecision{
			{Fingerprint: "fp", ContextHash: "ctx", Verdict: "false_positive", DecidedAt: older},
		},
	}
	body, _ := json.Marshal(&imp)
	_ = os.WriteFile(src, body, 0o644)

	h := NewTriageHistory(filepath.Join(dir, "local.json"))
	h.Add(TriageDecision{Fingerprint: "fp", ContextHash: "ctx", Verdict: "true_positive", DecidedAt: newer})

	changed, _ := h.Import(src)
	if changed != 0 {
		t.Errorf("expected 0 changed (older import), got %d", changed)
	}
	got, _ := h.Lookup("fp", "ctx")
	if got.Verdict != "true_positive" {
		t.Errorf("local newer decision should be preserved, got %s", got.Verdict)
	}
}

func TestSave_AtomicAndCreatesDir(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "deeper", "th.json")

	h := NewTriageHistory(path)
	h.Add(TriageDecision{Fingerprint: "fp", ContextHash: "ctx"})
	if err := h.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected file at %s, err=%v", path, err)
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp") {
			t.Errorf("temp file leaked: %s", e.Name())
		}
	}
}

func TestSave_FailsWithoutPath(t *testing.T) {
	h := &TriageHistory{}
	if err := h.Save(); err == nil {
		t.Errorf("expected error when path is empty")
	}
}

func TestHashContext_StableAndTrimsWhitespace(t *testing.T) {
	a := HashContext("foo")
	b := HashContext("  foo\n")
	if a != b {
		t.Errorf("hash should be whitespace-stable; %s != %s", a, b)
	}
	if HashContext("foo") == HashContext("bar") {
		t.Errorf("different inputs hashed identically")
	}
}

func TestFewShotExamples_RendersRecentFirst(t *testing.T) {
	got := FewShotExamples([]TriageDecision{
		{Verdict: "true_positive", AdjustedSeverity: "high", Rationale: "concatenated SQL"},
		{Verdict: "false_positive", AdjustedSeverity: "low", Rationale: "test fixture"},
	})
	if !strings.Contains(got, "1. verdict=true_positive") {
		t.Errorf("expected first example numbered 1; got %q", got)
	}
	if !strings.Contains(got, "concatenated SQL") || !strings.Contains(got, "test fixture") {
		t.Errorf("expected both rationales rendered; got %q", got)
	}
	if FewShotExamples(nil) != "" {
		t.Errorf("empty input should render empty string")
	}
}
