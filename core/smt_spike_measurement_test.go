package core

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// guardClasses names what DECIDING each kind of guard would require, coarsest
// first. The order is the classification: the first pattern that matches wins,
// so a cheap class listed above an expensive one must not be able to swallow it.
//
// Three classes were added on 2026-09-11, after the re-measurement showed 59% of
// guards landing in "unclassified". RESULT.md had already reclassified the same
// samples in prose — "`if i > 8` is an integer comparison; `switch`/`case` on a
// string is equality" — which meant the instrument could not answer its own
// question without a human pass, and a measurement kept executable so the
// question can be re-asked rather than re-argued has to be able to answer it.
var guardClasses = []struct {
	name string
	re   *regexp.Regexp
}{
	{"regex", regexp.MustCompile(`(?i)\b(MatchString|regexp?\.|re\.match|\.match\()`)},
	{"string", regexp.MustCompile(`(?i)\b(HasPrefix|HasSuffix|Contains|startswith|endswith|strings\.|\+\s*"|"\s*\+)`)},
	{"membership", regexp.MustCompile(`(?i)(\[[a-zA-Z_][\w.]*\]|\bin\b\s|Contains\()`)},
	{"length", regexp.MustCompile(`(?i)\b(len\(|\.length|\.size\(\))`)},
	// A shell test predicate asks the filesystem or the environment, not the
	// string. It needs a model of the world outside the program, which is a
	// different (and larger) problem from anything a solver addresses. Listed
	// above "interval" because shell redirection puts a bare `>` on lines that
	// have nothing to do with comparison.
	{"environment", regexp.MustCompile(`(\[\s+-[a-z]{1,2}\b|\btest\s+-[a-z]{1,2}\b|-n\s+"|-z\s+")`)},
	// An ordering comparison on a number: `if i > 8`. Interval reasoning, the
	// same requirement as "length", kept separate because the two are found by
	// different means and conflating them would hide which is which.
	{"interval", regexp.MustCompile(`(<=|>=|[<>])`)},
	// A switch or case on a string is equality, decided against a literal set.
	{"equality", regexp.MustCompile(`(==|!=|\bis\b|\bnot\b|^\s*(switch|case)\b)`)},
	{"call", regexp.MustCompile(`[a-zA-Z_][\w.]*\s*\(`)},
}

// classifyGuard names what deciding this guard would require, or "unclassified"
// when nothing matches. Extracted so the classification can be asserted
// directly — see TestGuardClassificationIsExercised — rather than only observed
// through a 27-repository scan.
func classifyGuard(line string) string {
	for _, c := range guardClasses {
		if c.re.MatchString(line) {
			return c.name
		}
	}
	return "unclassified"
}

// TestGuardClassificationIsExercised pins the classifier against the guards the
// two measurements actually produced, including every sample RESULT.md had to
// reclassify by hand.
//
// The instrument reports rather than asserts, which is right for a measurement
// and wrong for the measuring device: an unasserted classifier drifts, and the
// drift shows up as a shifting "unclassified" bucket that a reader attributes to
// the corpus.
func TestGuardClassificationIsExercised(t *testing.T) {
	cases := []struct{ line, want string }{
		// Reclassified by hand in the 2026-08-31 result; answered here now.
		{"		if i > 8 {", "interval"},
		{"	switch os.Args[1] {", "equality"},
		{`	case "compute":`, "equality"},
		// New in the 2026-09-11 re-measurement, once shell flows appeared.
		{"if [ -f /secrets/forge_email ] && [ -f /secrets/forge_token ]; then", "environment"},
		{`if [ -z "$TOKEN" ]; then`, "environment"},
		// The classes that already worked must keep working, and must keep
		// winning over the ones added below them.
		{"	if len(x) > 8 {", "length"},
		{`	if x == "" {`, "equality"},
		{"	if isValid(x) {", "call"},
		{"	if strings.HasPrefix(p, pfx) {", "string"},
		{"	if re.MatchString(s) {", "regex"},
		{"	if allowed[name] {", "membership"},
		// A guard nothing models: the honest answer is still "unclassified".
		{"	if {", "unclassified"},
		// `if !ok` is a boolean from an earlier call the window cannot see.
		// Deciding it needs whatever produced `ok`, which is not on this line,
		// so unclassified is the honest answer rather than a guessed class.
		{"	if !ok {", "unclassified"},
	}
	for _, tc := range cases {
		if got := classifyGuard(tc.line); got != tc.want {
			t.Errorf("classifyGuard(%q) = %q, want %q", strings.TrimSpace(tc.line), got, tc.want)
		}
	}
}

// TestProseAboutAConditionIsNotACondition. condRe's `\bif\s` alternative
// matches the word anywhere on the line, so a comment discussing a condition
// counted as a guard — inflating both the guard total and the share of flows
// reported as guarded.
func TestProseAboutAConditionIsNotACondition(t *testing.T) {
	comments := []string{
		"#   (b) Heuristic: if a Pod's env / configmap references another",
		"// if the caller already validated this, skip",
		"-- if the row is absent we insert",
		" * if x is nil this returns early",
	}
	for _, c := range comments {
		if !commentRe.MatchString(c) {
			t.Errorf("not recognised as a comment, so it is counted as a guard: %q", c)
		}
	}
	// A real conditional that carries a trailing comment is still a guard.
	for _, code := range []string{
		"if [ -f /etc/passwd ]; then # check",
		"	if x == y { // equal",
	} {
		if commentRe.MatchString(code) {
			t.Errorf("a conditional with a trailing comment was dropped: %q", code)
		}
		if !condRe.MatchString(code) {
			t.Errorf("fixture: %q should match condRe", code)
		}
	}
}

var condRe = regexp.MustCompile(`^\s*(if|else if|elif|while|switch|case)\b|\bif\s`)

// commentRe matches a line whose first non-space character opens a comment.
//
// The 2026-09-11 re-measurement counted `#   (b) Heuristic: if a Pod's env ...`
// as a guard, because condRe's `\bif\s` alternative matches the word "if"
// anywhere. Prose about a condition is not a condition — the same mistake nox
// fixed in its own IaC rules (#599), found here in the instrument that measures
// them.
var commentRe = regexp.MustCompile(`^\s*(//|#|--|;;|\*|/\*)`)

// TestSMTSpikeMeasureGuards is the measurement behind
// docs/research/smt-spike/RESULT.md, kept executable so the question can be
// re-asked rather than re-argued.
//
// It reports rather than asserts, with one exception: it fails if the corpora
// produce no taint flows at all, because then it is measuring nothing. Re-run
// it if the taint engine's recall changes materially — the recommendation
// (do not adopt SMT) rests on flows being 1% of findings, and that is the
// number that would move.
func TestSMTSpikeMeasureGuards(t *testing.T) {
	if testing.Short() {
		t.Skip("scans many repositories; skipped in -short")
	}
	targets := []string{
		"../testdata/precision-suite", "../testdata/refutation-hard", "..",
	}
	home, _ := os.UserHomeDir()
	for _, r := range []string{
		"mnemos", "scout", "keyward", "bolt", "coverctl", "agent-go", "armada",
		"briefkasten", "chronos", "decisionkit", "episteme", "fortify", "kiln",
		"mcp-go", "proctor", "statekit", "glossa", "dispatch", "skene",
		"auth-go", "axi-go", "senat-os", "vorhut", "studio", "brotwerk",
	} {
		targets = append(targets, filepath.Join(home, "Developer", "klarlabs", "oss", r))
	}

	classCount := map[string]int{}
	var unclassified []string
	var flows, withGuard, guardsTotal, allFindings, reposScanned int
	byLang := map[string]int{}

	for _, tgt := range targets {
		if _, err := os.Stat(tgt); err != nil {
			continue
		}
		res, err := RunScanWithOptions(tgt, ScanOptions{Offline: true})
		if err != nil {
			continue
		}
		reposScanned++
		allFindings += len(res.Findings.Findings())
		for _, f := range res.Findings.Findings() {
			if !strings.HasPrefix(f.RuleID, "TAINT-") {
				continue
			}
			flows++
			byLang[strings.TrimPrefix(filepath.Ext(f.Location.FilePath), ".")]++

			full := f.Location.FilePath
			if !filepath.IsAbs(full) {
				full = filepath.Join(ConfigRoot(tgt), full)
			}
			b, err := os.ReadFile(full)
			if err != nil {
				continue
			}
			lines := strings.Split(string(b), "\n")
			// Window: a bounded region above the sink. The source line is not
			// recorded on the finding, so the enclosing region is approximated.
			// This both over-counts (branches not on the path) and under-counts
			// (guards in a caller); it is good enough to establish that string
			// and regex guards are absent, not to price them precisely.
			hi := f.Location.StartLine
			lo := max(0, hi-40)
			var found int
			for i := lo; i < hi && i < len(lines); i++ {
				line := lines[i]
				if commentRe.MatchString(line) || !condRe.MatchString(line) {
					continue
				}
				found++
				guardsTotal++
				class := classifyGuard(line)
				classCount[class]++
				if class == "unclassified" && len(unclassified) < 6 {
					unclassified = append(unclassified, strings.TrimSpace(line))
				}
			}
			if found > 0 {
				withGuard++
			}
		}
	}

	if flows == 0 {
		t.Fatal("no taint flows found anywhere; this measurement is reporting on an " +
			"empty set and its conclusion would be vacuous")
	}
	t.Logf("repositories/corpora scanned: %d", reposScanned)
	t.Logf("findings of every kind: %d", allFindings)
	t.Logf("taint flows examined: %d (%.1f%% of all findings)", flows, pct(flows, allFindings))
	t.Logf("flows with >=1 guard between source and sink: %d (%.0f%%)",
		withGuard, pct(withGuard, flows))
	t.Logf("guards total: %d", guardsTotal)
	var names []string
	for k := range classCount {
		names = append(names, k)
	}
	sort.Slice(names, func(i, j int) bool { return classCount[names[i]] > classCount[names[j]] })
	for _, n := range names {
		t.Logf("  %-11s %4d (%.0f%% of guards)", n, classCount[n], pct(classCount[n], guardsTotal))
	}
	for _, u := range unclassified {
		t.Logf("  unclassified sample: %s", u[:min(72, len(u))])
	}
	var langs []string
	for k := range byLang {
		langs = append(langs, k)
	}
	sort.Slice(langs, func(i, j int) bool { return byLang[langs[i]] > byLang[langs[j]] })
	for _, l := range langs {
		t.Logf("  lang .%-6s %d flows", l, byLang[l])
	}
}

func pct(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return 100 * float64(a) / float64(b)
}
