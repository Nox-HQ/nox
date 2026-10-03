package main

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/bench"
)

// Declared corpus provenance is a supplied fact that nox carries and shows and
// does nothing else with. These tests hold the "nothing else": the same corpus
// with and without a manifest must give the same scans, the same counts, the
// same rule-review and the same calibration. Only the declarations themselves,
// in the report, may differ.
//
// Why it is held this hard: docs/research/evidence-independence/RESULT.md found
// that independence cannot be inferred from findings, and the obvious next step
// -- "now that it is declared, weight by it" -- would quietly rebuild the
// rejected metric on top of these declarations. That needs its own evidence
// first, and it should arrive as a visible change to these tests, not as a
// helper that happens to read the field.

const guardManifest = `version: 1
projects:
  alpha:
    - path: docs/v1/
      provenance:
        kind: versioned
        source: docs/v2/
        basis: docs.json lists v1 and v2, v2 the default
  beta:
    - path: src/types/
      provenance:
        kind: generated
        upstream: https://example.invalid/openapi.yml
        basis: every file carries the generator header
`

type scanCall struct{ exe, project string }

// fakeBenchScan stands in for the real scan, records exactly what each scan
// was given, and returns a summary with a collapse in it so rule-review has a
// prevalence row to report.
func fakeBenchScan(t *testing.T) *[]scanCall {
	t.Helper()
	var calls []scanCall
	orig := benchScan
	benchScan = func(exe, project string) (ProjectSummary, error) {
		calls = append(calls, scanCall{exe, project})
		return ProjectSummary{
			Path:     project,
			Findings: 12,
			Duration: "1s",
			ByRule:   map[string]int{"AI-031": 9, "SEC-161": 3},
			BySite:   map[string]int{"AI-031": 2, "SEC-161": 3},
			BySev:    map[string]int{"medium": 12},
		}, nil
	}
	t.Cleanup(func() { benchScan = orig })
	return &calls
}

func guardCorpus(t *testing.T) string {
	t.Helper()
	corpus := t.TempDir()
	for _, f := range []string{
		"alpha/docs/v1/index.md", "alpha/docs/v2/index.md",
		"beta/src/types/a.py", "gamma/main.go",
	} {
		p := filepath.Join(corpus, filepath.FromSlash(f))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return corpus
}

func writeProvFile(t *testing.T, path, body string) string {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// benchRun runs `nox bench` and returns its exit code and report bytes.
func benchRun(t *testing.T, args ...string) (code int, report []byte) {
	t.Helper()
	out := filepath.Join(t.TempDir(), "report")
	code = runBench(append(args, "--output", out, "--quiet"))
	report, _ = os.ReadFile(out)
	return code, report
}

// withoutVolatile drops what legitimately differs between two runs (the clock)
// and, when asked, the declarations, so what remains must be identical.
func withoutVolatile(t *testing.T, raw []byte, dropDeclared bool) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("report is not JSON: %v", err)
	}
	delete(m, "started_at")
	delete(m, "finished_at")
	if dropDeclared {
		for _, p := range m["projects"].([]any) {
			delete(p.(map[string]any), "declared_provenance")
		}
	}
	return m
}

func TestBenchProvenance_ChangesNoScanAndNoCount(t *testing.T) {
	corpus := guardCorpus(t)
	manifest := writeProvFile(t, filepath.Join(t.TempDir(), "prov.yaml"), guardManifest)

	calls := fakeBenchScan(t)
	plainCode, plain := benchRun(t, "--corpus", corpus)
	plainCalls := append([]scanCall(nil), *calls...)
	*calls = nil
	declCode, decl := benchRun(t, "--corpus", corpus, "--provenance", manifest)

	if plainCode != 0 || declCode != 0 {
		t.Fatalf("exit codes: without %d, with %d; both must succeed identically", plainCode, declCode)
	}
	if !reflect.DeepEqual(plainCalls, *calls) || len(plainCalls) != 3 {
		t.Errorf("scans differ: without %v, with %v; a declaration must never reach a scan", plainCalls, *calls)
	}
	if a, b := withoutVolatile(t, plain, false), withoutVolatile(t, decl, true); !reflect.DeepEqual(a, b) {
		t.Errorf("report differs beyond declared_provenance:\nwithout: %v\nwith:    %v", a, b)
	}

	// The one permitted difference, and it must be the declarations verbatim.
	var report BenchReport
	if err := json.Unmarshal(decl, &report); err != nil {
		t.Fatal(err)
	}
	want, err := bench.LoadCorpusProvenance(manifest)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range report.Projects {
		name := filepath.Base(p.Path)
		if !reflect.DeepEqual(p.DeclaredProvenance, want.Projects[name]) {
			t.Errorf("%s: declared_provenance = %v, want %v", name, p.DeclaredProvenance, want.Projects[name])
		}
	}
	if strings.Contains(string(plain), "declared_provenance") {
		t.Error("a report without a manifest mentions declared_provenance; an existing corpus must be unchanged")
	}
}

// rule-review and calibrate read bench reports. Fed the report with and without
// declarations, at the same path, their output must be byte-identical.
func TestBenchProvenance_ChangesNoDownstreamReading(t *testing.T) {
	corpus := guardCorpus(t)
	manifest := writeProvFile(t, filepath.Join(t.TempDir(), "prov.yaml"), guardManifest)
	fakeBenchScan(t)
	_, plain := benchRun(t, "--corpus", corpus)
	_, decl := benchRun(t, "--corpus", corpus, "--provenance", manifest)

	readers := map[string]func(report string) []string{
		"rule-review --json": func(r string) []string { return []string{"--bench", r, "--json"} },
		"rule-review --all":  func(r string) []string { return []string{"--bench", r, "--all"} },
		"calibrate":          func(r string) []string { return []string{"--bench", r, "--min-projects", "1"} },
	}
	run := map[string]func([]string) int{
		"rule-review --json": runRuleReview, "rule-review --all": runRuleReview, "calibrate": runCalibrate,
	}
	dir := t.TempDir()
	reportPath := filepath.Join(dir, "bench.json")
	for name, args := range readers {
		outputs := make([][]byte, 2)
		codes := make([]int, 2)
		for i, report := range [][]byte{plain, decl} {
			writeProvFile(t, reportPath, string(report))
			out := filepath.Join(dir, "out")
			codes[i] = run[name](append(args(reportPath), "--output", out))
			outputs[i], _ = os.ReadFile(out)
		}
		if codes[0] != codes[1] {
			t.Errorf("%s: exit %d without declarations, %d with", name, codes[0], codes[1])
		}
		if len(outputs[0]) == 0 {
			t.Errorf("%s: produced nothing, so the comparison proves nothing", name)
		}
		if !bytes.Equal(outputs[0], outputs[1]) {
			t.Errorf("%s output changed when declarations were present:\n--- without\n%s\n--- with\n%s",
				name, outputs[0], outputs[1])
		}
	}
}

// The markdown report gains one section and nothing else changes.
func TestBenchProvenance_MarkdownAddsOnlyItsSection(t *testing.T) {
	corpus := guardCorpus(t)
	manifest := writeProvFile(t, filepath.Join(t.TempDir(), "prov.yaml"), guardManifest)
	fakeBenchScan(t)
	_, plain := benchRun(t, "--corpus", corpus, "--format", "markdown")
	_, decl := benchRun(t, "--corpus", corpus, "--format", "markdown", "--provenance", manifest)

	clock := func(s string) string {
		var keep []string
		for _, l := range strings.Split(s, "\n") {
			if !strings.HasPrefix(l, "- Started:") && !strings.HasPrefix(l, "- Finished:") {
				keep = append(keep, l)
			}
		}
		return strings.Join(keep, "\n")
	}
	p, d := clock(string(plain)), clock(string(decl))
	const heading = "\n## Declared provenance\n"
	if strings.Contains(p, heading) {
		t.Error("a report without a manifest has a declared-provenance section")
	}
	start := strings.Index(d, heading)
	if start < 0 {
		t.Fatalf("no declared-provenance section:\n%s", d)
	}
	section := d[start:]
	if next := strings.Index(section[len(heading):], "\n## "); next >= 0 {
		section = section[:len(heading)+next]
	}
	for _, want := range []string{"| alpha | `docs/v1/` | versioned | docs/v2/ |", "(upstream)", "not measured"} {
		if !strings.Contains(section, want) {
			t.Errorf("section lacks %q:\n%s", want, section)
		}
	}
	if strings.Replace(d, section, "", 1) != p {
		t.Errorf("markdown differs outside the declared-provenance section")
	}
}

// An invalid manifest fails before a single scan runs and writes no report.
func TestBenchProvenance_InvalidManifestFailsBeforeScanning(t *testing.T) {
	corpus := guardCorpus(t)
	cases := map[string]string{
		"unsupported kind": strings.Replace(guardManifest, "kind: generated", "kind: mirrored", 1),
		"missing path":     strings.Replace(guardManifest, "src/types/", "src/gone/", 1),
		"unknown project":  strings.Replace(guardManifest, "  beta:", "  delta:", 1),
		"unreadable":       "version: [",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			calls := fakeBenchScan(t)
			manifest := writeProvFile(t, filepath.Join(t.TempDir(), "prov.yaml"), body)
			code, report := benchRun(t, "--corpus", corpus, "--provenance", manifest)
			if code != 2 {
				t.Errorf("exit %d, want 2", code)
			}
			if len(*calls) != 0 {
				t.Errorf("%d scans ran before the manifest was rejected", len(*calls))
			}
			if len(report) != 0 {
				t.Error("a report was written despite an invalid manifest")
			}
		})
	}
}

// The declarations have exactly one reader: the bench report that shows them.
// A second Go file referring to them is the point where a declaration starts to
// affect something, and that is a design change -- see the comment at the top
// of this file -- not a refactor.
func TestCorpusProvenanceHasOneReader(t *testing.T) {
	allowed := map[string]bool{
		"cli/bench_cmd.go":         true, // carries and renders them
		"core/bench/provenance.go": true, // defines them
	}
	needles := []string{"DeclaredProvenance", "CorpusProvenance", "DeclaredSource", "ProvenanceKind"}
	var readers []string
	err := filepath.WalkDir("..", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "testdata", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, n := range needles {
			if strings.Contains(string(src), n) {
				readers = append(readers, filepath.ToSlash(strings.TrimPrefix(path, "../")))
				break
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(readers)
	for _, r := range readers {
		if !allowed[r] {
			t.Errorf("%s refers to declared corpus provenance; nothing may read it but the bench report", r)
		}
	}
	if len(readers) != len(allowed) {
		t.Errorf("readers = %v, want exactly %d files; if one moved, update this list deliberately",
			readers, len(allowed))
	}
}

// The shipped autocorpus manifest names only projects the curated corpus
// clones, under the directory names --autocorpus gives them.
func TestShippedProvenanceNamesCuratedProjects(t *testing.T) {
	m, err := bench.LoadCorpusProvenance("../docs/benchmarks/corpus-provenance.yaml")
	if err != nil {
		t.Fatal(err)
	}
	curated := map[string]bool{}
	for _, e := range curatedAutoCorpus {
		owner, repo := splitRepoSlug(e.Repo)
		curated[owner+"--"+repo] = true
	}
	for _, name := range m.ProjectNames() {
		if !curated[name] {
			t.Errorf("manifest declares %q, which --autocorpus does not clone", name)
		}
	}
}
