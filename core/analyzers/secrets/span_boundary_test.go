package secrets

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"sort"
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

// An imported rule's trailing boundary group consumes the delimiter after a
// token. When that delimiter was a newline, the finding's span ended at
// column 1 of the next line, and dedup -- which compares same-line spans by
// column -- saw it overlap nothing. One unquoted token was then reported once
// per rule that matched it.

// seededSpanJWT is a structurally valid HS256 JWT from a fixed seed.
func seededSpanJWT() string {
	r := rand.New(rand.NewSource(819))
	enc := base64.RawURLEncoding
	claims, _ := json.Marshal(map[string]any{"sub": fmt.Sprintf("u%09d", r.Intn(1e9)), "iat": 1759500000})
	sig := make([]byte, 32)
	r.Read(sig)
	return enc.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`)) + "." + enc.EncodeToString(claims) + "." + enc.EncodeToString(sig)
}

// seededAdminKey has SEC-166's Anthropic admin-key shape, from a fixed seed.
func seededAdminKey() string {
	r := rand.New(rand.NewSource(166))
	const alpha = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
	b := make([]byte, 93)
	for i := range b {
		b[i] = alpha[r.Intn(len(alpha))]
	}
	return "sk-ant-admin01-" + string(b) + "AA"
}

// line1Findings runs the full per-file pipeline (ScanArtifacts: refiners
// and dedup), which is what a user sees; ScanFile is the raw engine output.
func line1Findings(t *testing.T, name, body string) []findings.Finding {
	t.Helper()
	fs, _ := scanRecording(t, name, body)
	var out []findings.Finding
	for _, f := range fs.Findings() {
		if f.Location.StartLine == 1 {
			out = append(out, f)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RuleID < out[j].RuleID })
	return out
}

func ids(fs []findings.Finding) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.RuleID
	}
	return out
}

// TestUnquotedTokenBeforeANewlineIsReportedOnce: the same token, quoted and
// unquoted, must produce the same single finding. Before the fix the
// unquoted forms produced two (YAML JWT) and three (.env admin key).
func TestUnquotedTokenBeforeANewlineIsReportedOnce(t *testing.T) {
	jwt, admin := seededSpanJWT(), seededAdminKey()
	tests := []struct{ name, file, body string }{
		{"yaml jwt unquoted", "config.yaml", "value: " + jwt + "\nnext: x\n"},
		{"yaml jwt quoted", "config.yaml", "value: \"" + jwt + "\"\nnext: x\n"},
		{"env admin key unquoted", "app.env", "ADMIN_KEY=" + admin + "\nOTHER=1\n"},
		{"yaml admin key quoted", "config.yaml", "admin: \"" + admin + "\"\nother: 1\n"},
		{"yaml admin key unquoted", "config.yaml", "admin: " + admin + "\nother: 1\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := line1Findings(t, tt.file, tt.body)
			if len(got) != 1 {
				t.Fatalf("one token, %d findings: %v", len(got), ids(got))
			}
		})
	}
}

// TestUnquotedTokenSpanEndsAtTheToken: the reported span is the token, not
// the newline after it.
func TestUnquotedTokenSpanEndsAtTheToken(t *testing.T) {
	admin := seededAdminKey()
	for _, f := range line1Findings(t, "app.env", "ADMIN_KEY="+admin+"\nOTHER=1\n") {
		if f.RuleID != "SEC-166" {
			continue
		}
		l := f.Location
		if l.EndLine != 1 || l.EndColumn != len("ADMIN_KEY=")+1+len(admin) {
			t.Fatalf("SEC-166 span %d:%d-%d:%d, want it to end at 1:%d", l.StartLine, l.StartColumn, l.EndLine, l.EndColumn, len("ADMIN_KEY=")+1+len(admin))
		}
		return
	}
	t.Fatal("SEC-166 did not report the admin key")
}
