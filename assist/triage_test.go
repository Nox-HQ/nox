package assist

import (
	"strings"
	"testing"
)

func TestBuildTriagePrompt_StructureAndContent(t *testing.T) {
	msgs := BuildTriagePrompt(TriageContext{
		RuleID:       "SEC-002",
		Title:        "SQL injection",
		Severity:     "high",
		FilePath:     "repo/db.go",
		Line:         42,
		Snippet:      `db.Query("SELECT * FROM users WHERE id = " + userID)`,
		CodeContext:  "func Lookup(userID string) {\n  ...\n}",
		BaseScore:    7.5,
		Confidence:   "high",
		BusinessTags: []string{"customer-data", "production"},
	})
	if len(msgs) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(msgs))
	}
	if msgs[0].Role != RoleSystem {
		t.Errorf("first message must be system, got %s", msgs[0].Role)
	}
	if !strings.Contains(msgs[0].Content, "static-analysis") {
		t.Errorf("system prompt missing triage framing: %q", msgs[0].Content)
	}
	if !strings.Contains(msgs[0].Content, "true_positive") {
		t.Errorf("system prompt should constrain output to JSON schema")
	}

	user := msgs[1].Content
	for _, want := range []string{
		"SEC-002",
		"SQL injection",
		"high",
		"repo/db.go:42",
		"7.5",
		"customer-data",
		"db.Query",
		"func Lookup",
	} {
		if !strings.Contains(user, want) {
			t.Errorf("user prompt missing %q\nfull prompt:\n%s", want, user)
		}
	}
}

func TestBuildTriagePrompt_OmitsEmptyFields(t *testing.T) {
	msgs := BuildTriagePrompt(TriageContext{
		RuleID: "SEC-001",
		Title:  "shell injection",
	})
	user := msgs[1].Content
	if strings.Contains(user, "Location:") {
		t.Errorf("Location section must be omitted when no FilePath; got %q", user)
	}
	if strings.Contains(user, "Surrounding code") {
		t.Errorf("Surrounding-code section must be omitted when CodeContext empty")
	}
	if strings.Contains(user, "Matched snippet") {
		t.Errorf("Snippet section must be omitted when Snippet empty")
	}
	if !strings.Contains(user, "SEC-001") || !strings.Contains(user, "shell injection") {
		t.Errorf("rule id + title must always appear; got %q", user)
	}
}
