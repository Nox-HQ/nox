package bench

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// A Branch is one way nox can decide that a candidate is NOT a finding.
//
// Every branch here is a place where the scanner concludes something did not
// matter. That conclusion is the product's value and its most dangerous
// failure: a refutation that is slightly wrong removes a real vulnerability
// while every metric anyone watches improves. Precision rises, counts fall,
// and nothing goes red.
//
// The registry exists so that the corpus cannot silently stop covering one of
// them. A coverage check that only walked the fixtures would pass trivially
// once the last fixture for a branch was deleted — the branch would vanish
// along with its evidence, which is the empty-set success this whole programme
// is written against. Declaring the universe in code and the witnesses in
// testdata means deleting a fixture leaves a registered branch with nothing
// covering it, and the check fails naming it.
//
// Adding a branch before its fixture is the intended order: the failing check
// is the specification.
type Branch struct {
	// ID is the stable slug a fixture names in its `nox-cover:` annotation.
	ID string
	// Corpus is the corpus directory, relative to testdata/, that must hold at
	// least one fixture covering this branch.
	Corpus string
	// Wrong is the tempting-but-incorrect reasoning this branch's fixture
	// exists to catch. It is the sentence a reviewer must disagree with before
	// deleting the fixture.
	Wrong string
	// Family is the rule family the branch removes findings from.
	Family string
	// Matcher names the evaluation path the refutation runs on, because the
	// same declared semantics behave differently on different paths — the
	// reason Milestone 0.5 exists.
	Matcher string
	// Proposition is what the refutation actually establishes. Keeping it
	// explicit is what stops evidence about one fact from settling another.
	Proposition string
}

// RefutationBranches is the declared universe of refutation branches.
//
// Ordered by corpus, then by the milestone that introduced the branch.
var RefutationBranches = []Branch{
	{
		ID: "lexical-context", Corpus: "refutation-suite",
		Wrong:  "a lexer that starts a comment at the first bare # rather than tracking string state swallows a sink whose argument holds a \"#\" literal",
		Family: "TAINT", Matcher: "lexctx",
		Proposition: "this text is a comment, not code",
	},
	{
		ID: "generated-code", Corpus: "refutation-suite",
		Wrong:  "greping the whole file for a generated-code banner rather than requiring it in the leading comment block, which skips hand-written code most reliably in code that writes code",
		Family: "TAINT", Matcher: "file-prefilter",
		Proposition: "this file is machine-generated, so its contents are not authored risk",
	},
	{
		ID: "constant-evaluation", Corpus: "refutation-suite",
		Wrong:  "resolving one operand of a concatenation to a literal and stopping",
		Family: "TAINT", Matcher: "consteval",
		Proposition: "this value is a compile-time constant",
	},
	{
		ID: "sanitizer-recognition", Corpus: "refutation-suite",
		Wrong:  "proximity is not dataflow: a sanitizer running one line above the sink, on a different variable",
		Family: "TAINT", Matcher: "taint/structural",
		Proposition: "the value reaching this sink was neutralized for this vulnerability class",
	},
	{
		ID: "flow-identity", Corpus: "refutation-suite",
		Wrong:  "one tainted value reaching two sinks on consecutive lines shares every cheap merge signal but is two vulnerabilities with two fixes",
		Family: "TAINT", Matcher: "dedup",
		Proposition: "these two observations are one security condition",
	},
	{
		ID: "interprocedural-scope", Corpus: "refutation-suite",
		Wrong:  "an intraprocedural check finds no source-to-sink flow in either function and concludes the code is safe, while the sink sits behind a one-line wrapper",
		Family: "TAINT", Matcher: "taint/structural",
		Proposition: "no flow connects a source to a sink",
	},
	{
		ID: "value-semantics", Corpus: "refutation-suite",
		Wrong:  "an identifier that says EXAMPLE or SAMPLE describes the value bound to it",
		Family: "SEC", Matcher: "secrets/refiner",
		Proposition: "this literal is a placeholder, not a credential",
	},
	{
		ID: "absence-subject-precondition", Corpus: "refutation-suite",
		Wrong:  "a precondition that correctly exempts one subject is widened until it exempts subjects the rule was written for",
		Family: "IAC", Matcher: "absence/structural",
		Proposition: "this rule does not apply to this subject",
	},
	{
		ID: "absence-resource-kind", Corpus: "refutation-suite",
		Wrong:  "a rule narrowed off one workload kind is narrowed off the kinds it was written for",
		Family: "IAC", Matcher: "absence/structural",
		Proposition: "this rule does not apply to this resource kind",
	},
	{
		ID: "absence-kind-still-governed", Corpus: "refutation-suite",
		Wrong:  "narrowing SOME rules off a resource kind is generalized into that kind being exempt from hardening",
		Family: "IAC", Matcher: "absence/structural",
		Proposition: "the rules that do apply to this kind still apply",
	},
	{
		ID: "sanitizer-pipeline-producer", Corpus: "refutation-suite",
		Wrong:  "a quoting producer upstream in a pipeline is generalized from the exact call that quotes to any call by the same name",
		Family: "TAINT", Matcher: "taint/shell-extractor",
		Proposition: "an upstream pipeline segment quoted this value for the downstream parser",
	},
	{
		ID: "unmodelled-reflection", Corpus: "refutation-hard",
		Wrong:  "no flow found through MethodByName is reported as no flow exists",
		Family: "TAINT", Matcher: "taint/structural",
		Proposition: "the callee is undetermined, so the search was not exhaustive",
	},
	{
		ID: "unmodelled-dynamic-dispatch", Corpus: "refutation-hard",
		Wrong:  "the concrete type behind an interface is assumed to be the only one the analysis saw",
		Family: "TAINT", Matcher: "taint/structural",
		Proposition: "the concrete callee is chosen from data, not from the text",
	},
	{
		ID: "unmodelled-bounded-loop", Corpus: "refutation-hard",
		Wrong:  "a bounded unrolling that did not reach the flow is reported as the flow not existing",
		Family: "TAINT", Matcher: "taint/structural",
		Proposition: "the analysis budget, not the program, ended the search",
	},
	{
		ID: "unmodelled-indirection", Corpus: "refutation-hard",
		Wrong:  "a value leaving through a pointer the analysis cannot model is treated as a value that did not leave",
		Family: "TAINT", Matcher: "taint/structural",
		Proposition: "the value escaped through an unmodelled construct",
	},
	{
		ID: "unmodelled-dynamic-loading", Corpus: "refutation-hard",
		Wrong:  "code that does not exist at analysis time is treated as code that does not exist",
		Family: "TAINT", Matcher: "taint/structural",
		Proposition: "the callee is not present in the analyzed program",
	},
}

// coverMarker matches `nox-cover: <branch-id>[, <branch-id>...]`, the fixture
// side of the registry above. It is deliberately the same shape as
// expectMarker: an inline annotation, in the file, next to what it describes,
// so the ground truth cannot drift away from the sample the way a separate
// manifest can.
var coverMarker = regexp.MustCompile(`(?i)nox-cover\s*:\s*(.*)$`)

// CoverageClaim is one fixture's declaration that it covers a branch.
type CoverageClaim struct {
	BranchID string
	Corpus   string
	FilePath string
	Line     int
}

// ParseCoverage walks a corpus directory and returns every `nox-cover` claim.
// Documentation files and harness artifacts are skipped for the same reason
// ParseCorpus skips them: a README explaining the annotation must not be able
// to satisfy the coverage it documents.
func ParseCoverage(dir string) ([]CoverageClaim, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("bench: coverage dir: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("bench: coverage path %q is not a directory", dir)
	}

	corpus := filepath.Base(dir)
	var claims []CoverageClaim
	walkErr := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, relErr := filepath.Rel(dir, path)
		if relErr != nil {
			return relErr
		}
		rel = filepath.ToSlash(rel)
		if IsNonSample(rel) {
			return nil
		}
		lines, readErr := readLines(path)
		if readErr != nil {
			return readErr
		}
		for i, line := range lines {
			for _, id := range parseCoverIDs(line) {
				claims = append(claims, CoverageClaim{
					BranchID: id, Corpus: corpus, FilePath: rel, Line: i + 1,
				})
			}
		}
		return nil
	})
	if walkErr != nil {
		return nil, fmt.Errorf("bench: walking coverage: %w", walkErr)
	}
	return claims, nil
}

// parseCoverIDs returns the branch IDs declared on a line, or nil.
func parseCoverIDs(line string) []string {
	m := coverMarker.FindStringSubmatch(line)
	if m == nil {
		return nil
	}
	fields := strings.FieldsFunc(m[1], func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t'
	})
	var ids []string
	for _, f := range fields {
		if f = strings.TrimSpace(f); f != "" {
			ids = append(ids, f)
		}
	}
	return ids
}

// CoverageReport is the result of checking a branch registry against the
// fixtures that claim to cover it.
type CoverageReport struct {
	// Uncovered lists registered branches no fixture claims. This is the
	// failure the registry exists to produce: deleting the last fixture for a
	// branch leaves the branch declared and unwitnessed.
	Uncovered []Branch
	// Unknown lists claims naming a branch that is not registered — a typo, or
	// a fixture left behind by a branch that was renamed or removed.
	Unknown []CoverageClaim
	// Misfiled lists claims made in a corpus other than the one the branch
	// declares. A fixture in the wrong corpus is scored by the wrong guard.
	Misfiled []CoverageClaim
	// Covered maps branch ID to the fixtures covering it.
	Covered map[string][]CoverageClaim
}

// OK reports whether coverage is complete and consistent.
func (r CoverageReport) OK() bool {
	return len(r.Uncovered) == 0 && len(r.Unknown) == 0 && len(r.Misfiled) == 0
}

// CheckCoverage verifies a branch registry against the fixtures under root
// (typically "testdata"). It reads each corpus named by the registry exactly
// once, so a branch pointing at a corpus that does not exist is an error rather
// than a silent pass.
func CheckCoverage(root string, branches []Branch) (CoverageReport, error) {
	report := CoverageReport{Covered: map[string][]CoverageClaim{}}
	if len(branches) == 0 {
		return report, fmt.Errorf("bench: empty branch registry; a coverage check over no branches passes vacuously")
	}

	registry := make(map[string]Branch, len(branches))
	corpora := map[string]bool{}
	for _, b := range branches {
		if b.ID == "" || b.Corpus == "" {
			return report, fmt.Errorf("bench: branch %+v must declare an ID and a corpus", b)
		}
		if _, dup := registry[b.ID]; dup {
			return report, fmt.Errorf("bench: duplicate branch ID %q", b.ID)
		}
		registry[b.ID] = b
		corpora[b.Corpus] = true
	}

	var allClaims []CoverageClaim
	for corpus := range corpora {
		claims, err := ParseCoverage(filepath.Join(root, corpus))
		if err != nil {
			return report, err
		}
		allClaims = append(allClaims, claims...)
	}

	for _, c := range allClaims {
		b, known := registry[c.BranchID]
		switch {
		case !known:
			report.Unknown = append(report.Unknown, c)
		case b.Corpus != c.Corpus:
			report.Misfiled = append(report.Misfiled, c)
		default:
			report.Covered[c.BranchID] = append(report.Covered[c.BranchID], c)
		}
	}

	for _, b := range branches {
		if len(report.Covered[b.ID]) == 0 {
			report.Uncovered = append(report.Uncovered, b)
		}
	}

	sort.Slice(report.Unknown, func(i, j int) bool {
		return report.Unknown[i].FilePath < report.Unknown[j].FilePath
	})
	sort.Slice(report.Misfiled, func(i, j int) bool {
		return report.Misfiled[i].FilePath < report.Misfiled[j].FilePath
	})
	return report, nil
}

// readLines reads a file into lines, tolerating the long lines corpus samples
// carry (minified bundles, base64 blobs).
func readLines(path string) ([]string, error) {
	data, err := os.ReadFile(path) //nolint:gosec // corpus paths are operator-supplied, not user input
	if err != nil {
		return nil, err
	}
	return strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n"), nil
}
