package secrets

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/nox-hq/nox/core/discovery"
)

// TestScanArtifacts_LexctxDropsEmbeddedBlob locks the live wiring: an AWS-key
// shape inside a data-blob string in source is dropped (the dominant secret
// false-positive class — a base64 SVG), while the same shape in an ordinary
// string literal and in a comment (a genuinely leaked credential) is kept.
func TestScanArtifacts_LexctxDropsEmbeddedBlob(t *testing.T) {
	const key = "AKIAIOSFODNN7EXAMPLE" // valid AKIA + [A-Z2-7]{16}
	cases := []struct {
		name string
		src  string
		want int
	}{
		{"real-secret-in-string", `const x = "` + key + `";` + "\n", 1},
		{"leaked-in-comment", "// note: " + key + "\n", 1},
		{
			"embedded-data-blob",
			`const b = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa /` + key + `/ bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";` + "\n",
			0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			abs := filepath.Join(dir, "a.ts")
			if err := os.WriteFile(abs, []byte(tc.src), 0o644); err != nil {
				t.Fatal(err)
			}
			art := discovery.Artifact{Path: "a.ts", AbsPath: abs, Type: discovery.Source}
			fs, err := NewAnalyzer().ScanArtifacts(context.Background(), []discovery.Artifact{art})
			if err != nil {
				t.Fatal(err)
			}
			got := 0
			items := fs.Findings()
			for i := range items {
				if len(items[i].RuleID) >= 4 && items[i].RuleID[:4] == "SEC-" {
					got++
				}
			}
			if got != tc.want {
				t.Errorf("%s: got %d SEC findings, want %d", tc.name, got, tc.want)
			}
		})
	}
}

// TestScanArtifacts_BareProviderPrefixDropped locks the fix that lets nox's own
// Go pattern-vocabulary files (core/analyzers/secrets/dedup.go) pass the self-
// scan without an exclude: a bare provider prefix that names a rule's vocabulary
// — `"glpat-"` in a string, `sk_live_` in a comment — is dropped, because a live
// credential always carries a 20+ char high-entropy body. A FULL token in a Go
// string is still reported (the regression guard: never silence a real secret).
func TestScanArtifacts_BareProviderPrefixDropped(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want int
	}{
		// The two shapes that tripped the #195 self-scan in dedup.go.
		{"bare-prefix-in-go-string", "var owners = map[string]string{\n\t\"glpat-\": \"SEC-018\",\n}\n", 0},
		{"bare-prefix-in-go-comment", "// prefix (ghp_, xoxb-, sk_live_, AKIA) resolution\nvar x = 1\n", 0},
		// Regression guard: a real hardcoded secret in an ordinary Go string is
		// STILL reported — a 20+ char body means it is not a bare prefix.
		{"real-secret-in-go-string", "apiKey := \"glpat-ABCDEFGHIJKLMNOPQRST\"\n", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			abs := filepath.Join(dir, "dedup_like.go")
			if err := os.WriteFile(abs, []byte(tc.src), 0o644); err != nil {
				t.Fatal(err)
			}
			art := discovery.Artifact{Path: "dedup_like.go", AbsPath: abs, Type: discovery.Source}
			fs, err := NewAnalyzer().ScanArtifacts(context.Background(), []discovery.Artifact{art})
			if err != nil {
				t.Fatal(err)
			}
			got := 0
			items := fs.Findings()
			for i := range items {
				if len(items[i].RuleID) >= 4 && items[i].RuleID[:4] == "SEC-" {
					got++
				}
			}
			if got != tc.want {
				t.Errorf("%s: got %d SEC findings, want %d", tc.name, got, tc.want)
			}
		})
	}
}
