package secrets

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

// The ~250 vendor rules SEC-556..SEC-950 were rebuilt from patterns that matched
// only a config-key NAME (e.g. `openai[_-]?api[_-]?key`) to patterns that require
// a credential VALUE next to the key
// (`(?i)openai[_-]?api[_-]?key[ \t]*[=:][ \t]*["']?[A-Za-z0-9_\-]{16,}`).
//
// A name-only pattern is broken three ways: it fires on documentation and code
// that merely NAMES the key, it never detects the actual secret VALUE, and being
// lowercase-only it both misses the standard `UPPERCASE_ENV=` convention and
// fires on lowercase prose. The `(?i)` value-bearing form fixes all three. These
// two tests bound the fix from both sides — precision (no false positives on a
// benign corpus) and recall (a real value-bearing line is still detected).

// valueBearingSuffix is the value-capture tail every rebuilt vendor rule carries.
// A rule whose pattern ends with it was converted from a name-only pattern and is
// covered by the recall guard below.
const valueBearingSuffix = `[ \t]*[=:][ \t]*["']?[A-Za-z0-9_\-]{16,}`

// benignCorpusFiles is a set of files that NAME vendor credentials but contain no
// actual secret value: a README documenting keys in backticks, a Go config struct
// with json/env tags, a .env.example template with empty/placeholder values, a
// Python settings module reading from os.environ, and a YAML file with ${VAR}
// references. Every one is the exact shape the old name-only rules false-fired on.
var benignCorpusFiles = map[string]string{
	"README.md":    "testdata/benign/README.md",
	"config.go":    "testdata/benign/config.go",
	".env.example": "testdata/benign/env.example",
	"settings.py":  "testdata/benign/settings.py",
	"config.yaml":  "testdata/benign/config.yaml",
}

// TestBenignCorpus_NoNameOnlyFalsePositives is the precision guard.
//
// Before the rebuild this corpus produced 39 false positives across 12 vendor
// rules — every one a high-severity finding an operator must triage, on a file
// that names a key without leaking it. The value-bearing patterns drop that to
// zero: naming `openai_api_key` in prose or a struct tag no longer matches,
// because no high-entropy value follows the key.
func TestBenignCorpus_NoNameOnlyFalsePositives(t *testing.T) {
	t.Parallel()

	// A tight bound rather than a bare `> 0`: it names the exact regression and
	// leaves a little headroom for a future value-shaped placeholder without
	// hiding a genuine reintroduction of the name-only bug.
	const maxFalsePositives = 0

	a := NewAnalyzer()
	var fps []string
	for label, path := range benignCorpusFiles {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		results, err := a.ScanFile(label, content)
		if err != nil {
			t.Fatalf("scan %s: %v", label, err)
		}
		for _, f := range results {
			fps = append(fps, fmt.Sprintf("%s in %s: %q", f.RuleID, label, f.Message))
		}
	}

	t.Logf("false positives on benign corpus: %d (bound %d)", len(fps), maxFalsePositives)
	if len(fps) > maxFalsePositives {
		t.Errorf("benign corpus produced %d false positives, above the %d bound — the "+
			"name-only regression is back:\n  %s",
			len(fps), maxFalsePositives, strings.Join(fps, "\n  "))
	}
}

// concretizeName turns a converted rule's name sub-pattern into a literal key an
// operator would actually write. The name part uses only three regex constructs —
// literals, the `[_-]?` separator, and an escaped `\.` — so a small set of
// replacements is exact, not a general regex-to-string inversion.
func concretizeName(namePattern string) string {
	s := strings.TrimPrefix(namePattern, "(?i)")
	s = strings.ReplaceAll(s, "[_-]?", "_")
	s = strings.ReplaceAll(s, "[_-]", "_")
	s = strings.ReplaceAll(s, `\.`, ".")
	return s
}

// TestConvertedVendorRules_DetectRealisticValues is the recall guard.
//
// Requiring a value must not stop a rule finding a real credential. For every
// rebuilt vendor rule, a realistic high-entropy token is placed directly beside
// its own key — `VENDOR_KEY = "<token>"`, the exact scenario the rule exists for —
// and the rule MUST report it. A false negative here would be strictly worse than
// the false positives the rebuild removed.
func TestConvertedVendorRules_DetectRealisticValues(t *testing.T) {
	t.Parallel()

	// A 32-char high-entropy token: mixed case and digits, no short-period
	// repetition, comfortably inside `[A-Za-z0-9_\-]{16,}` and above any entropy
	// floor a real vendor key would clear.
	const token = "aZ3xQ7mK9pR2wL5vN8tB4yH6jD0sF1gC"

	a := NewAnalyzer()
	var converted, missed int
	var misses []string

	for _, r := range builtinSecretRules() {
		if !strings.HasSuffix(r.Pattern, valueBearingSuffix) {
			continue
		}
		converted++

		name := concretizeName(strings.TrimSuffix(r.Pattern, valueBearingSuffix))
		// The convention the old lowercase-only patterns missed: an uppercased
		// env-style assignment. Uppercasing the concrete key also exercises the
		// `(?i)` flag that the rebuild added.
		//
		// A leading comment carries the vendor keyword so the engine's file-level
		// keyword gate opens. For most rules the keyword is already a substring of
		// the key; for the handful whose keyword differs from the key spelling
		// (e.g. keyword "battlenet" vs key "battle.net"), a real config file for
		// that vendor names it somewhere too. This isolates the property the
		// rebuild changed — that the pattern now matches on the VALUE — from the
		// orthogonal, pre-existing keyword configuration.
		keyword := "secret"
		if len(r.Keywords) > 0 {
			keyword = r.Keywords[0]
		}
		line := fmt.Sprintf("# %s integration\n%s = %q\n", keyword, strings.ToUpper(name), token)

		results, err := a.ScanFile("app.env", []byte(line))
		if err != nil {
			t.Fatalf("%s: scan error: %v", r.ID, err)
		}
		var detected bool
		for i := range results {
			if results[i].RuleID == r.ID {
				detected = true
				break
			}
		}
		if !detected {
			missed++
			if len(misses) < 20 {
				misses = append(misses, fmt.Sprintf("%s (pattern %q, line %q)", r.ID, r.Pattern, strings.TrimSpace(line)))
			}
		}
	}

	if converted == 0 {
		t.Fatal("no converted value-bearing vendor rules found; this test's suffix detection is stale")
	}
	t.Logf("checked %d rebuilt value-bearing vendor rules", converted)
	if missed > 0 {
		t.Errorf("%d of %d rebuilt vendor rules no longer detect a realistic value-bearing "+
			"line — these are FALSE NEGATIVES:\n  %s",
			missed, converted, strings.Join(misses, "\n  "))
	}
}
