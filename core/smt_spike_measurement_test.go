package core

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

var guardClasses = []struct {
	name string
	re   *regexp.Regexp
}{
	{"regex", regexp.MustCompile(`(?i)\b(MatchString|regexp?\.|re\.match|\.match\()`)},
	{"string", regexp.MustCompile(`(?i)\b(HasPrefix|HasSuffix|Contains|startswith|endswith|strings\.|\+\s*"|"\s*\+)`)},
	{"membership", regexp.MustCompile(`(?i)(\[[a-zA-Z_][\w.]*\]|\bin\b\s|Contains\()`)},
	{"length", regexp.MustCompile(`(?i)\b(len\(|\.length|\.size\(\))`)},
	{"equality", regexp.MustCompile(`(==|!=|\bis\b|\bnot\b)`)},
	{"call", regexp.MustCompile(`[a-zA-Z_][\w.]*\s*\(`)},
}

var condRe = regexp.MustCompile(`^\s*(if|else if|elif|while|switch|case)\b|\bif\s`)

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
				if !condRe.MatchString(line) {
					continue
				}
				found++
				guardsTotal++
				var hit bool
				for _, c := range guardClasses {
					if c.re.MatchString(line) {
						classCount[c.name]++
						hit = true
						break
					}
				}
				if !hit {
					classCount["unclassified"]++
					if len(unclassified) < 6 {
						unclassified = append(unclassified, strings.TrimSpace(line))
					}
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
