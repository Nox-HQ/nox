package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/nox-hq/nox/core/findings"
)

// curatedAutoCorpus is the default benchmark corpus when --autocorpus
// is set. Each entry targets the AI app developer ICP: LLM client
// SDKs (openai, anthropic), agent frameworks (langchain, llamaindex,
// crewai, agent-go, vercel-ai), and the MCP reference SDK.
//
// Pinned to immutable refs so bench output is reproducible across runs —
// asserted by TestCuratedCorpusIsPinnedToImmutableRefs, because the comment
// said this while half the list tracked `main`.
//
// LANGUAGE SPREAD IS PART OF THE POINT. nox ships source/sink catalogs for 21
// languages, and every one of them scores precision 1.000 / recall 1.000 on its
// own suite — a suite written to contain what nox detects cannot surface a gap.
// Real repositories can, and the corpus was Python and TypeScript only, so the
// six entries below were added to reach Java, Ruby, PHP, Rust, Kotlin and
// Swift. The first scan of one of them found SEC-505 firing 3,040 times on a
// single line
// (see contextCharWindow in core/rules/engine.go).
//
// Every entry was scanned before being added; a repo that reports nothing
// measures nothing. Findings at the pinned ref, measured 2026-09-12 on a fresh
// clone with `--output` pointed OUTSIDE the scanned tree:
//
//	langchain4j   156 findings, 13 taint flows   (Java)
//	ruby-openai   481 findings,  2 taint flows   (Ruby)
//	MacPaw/OpenAI 411 findings,  3 taint flows   (Swift)
//	async-openai  100 findings,  0 taint flows   (Rust)
//	openai-kotlin  38 findings,  0 taint flows   (Kotlin)
//	openai-php     20 findings,  0 taint flows   (PHP)
//
// The "outside the tree" part is load-bearing and was learned the hard way.
// `nox scan <dir> --output <dir>` writes findings.json and ai.inventory.json
// INTO the directory it just scanned, so a second scan reports on the first
// one's output: an earlier pass of this table had Rust at 141 rather than 100,
// the extra 41 being findings on nox's own artifacts. `--output` defaults to
// `.`, which makes the contaminating invocation the obvious one.
//
// openai/openai-dotnet was the C# candidate and is deliberately absent. It is
// also where this fix shows largest: 496,141 findings before the character
// bound and 5,030 after, both on clean trees. Even at 5,030 — 1,248 DATA-003,
// 766 SEC-161, 582 SEC-163, 503 SEC-629 — it is a noise profile to understand
// before it becomes a benchmark, not after, and the scan takes over ten
// minutes. The same reasoning keeps the 268 IAC-254 in the Swift entry: a
// corpus holding only quiet repositories measures nothing, so that count is a
// question the corpus now poses rather than one it hides.
var curatedAutoCorpus = []struct {
	Repo string
	Ref  string
}{
	{Repo: "langchain-ai/langchain", Ref: "v0.3.7"},
	{Repo: "run-llama/llama_index", Ref: "v0.12.0"},
	{Repo: "openai/openai-python", Ref: "v1.54.0"},
	{Repo: "anthropics/anthropic-sdk-python", Ref: "v0.40.0"},
	{Repo: "felixgeelhaar/agent-go", Ref: "v0.16.2"},
	{Repo: "modelcontextprotocol/python-sdk", Ref: "v2.2.0"},
	// vercel/ai is a monorepo; its tags are per-package, and this one names a
	// commit like any other tag.
	{Repo: "vercel/ai", Ref: "@ai-sdk/zai@3.0.10"},
	{Repo: "joaomdmoura/crewai", Ref: "1.15.21"},
	{Repo: "langchain4j/langchain4j", Ref: "1.20.0"},
	{Repo: "alexrudall/ruby-openai", Ref: "v8.3.0"},
	{Repo: "openai-php/client", Ref: "v0.20.1"},
	{Repo: "64bit/async-openai", Ref: "async-openai-v0.42.0"},
	{Repo: "aallam/openai-kotlin", Ref: "4.1.0"},
	{Repo: "MacPaw/OpenAI", Ref: "0.5.1"},
}

// runBench scans every directory in --corpus and produces a fire-rate
// report. With --autocorpus, nox first clones the curated benchmark
// set into a temp directory and runs the same harness against it —
// reproducible numbers without manual setup.
func runBench(args []string) int {
	// `nox bench --precision <corpus>` is a distinct mode: instead of
	// fire-rates over many projects, it scores one labeled corpus for
	// precision/recall/F1 against inline `nox-expect` ground truth. It is
	// routed early so it can own its own flag set without colliding with the
	// fire-rate flags (e.g. --min-precision, --json).
	if hasFlag(args, "precision") {
		return runBenchPrecision(args)
	}

	fs := flag.NewFlagSet("bench", flag.ContinueOnError)
	var (
		corpusDir  string
		output     string
		quiet      bool
		fmtFlag    string
		autoCorpus bool
	)
	fs.StringVar(&corpusDir, "corpus", "corpus", "directory containing one subdirectory per project to scan")
	fs.StringVar(&output, "output", "", "destination path (defaults to stdout)")
	fs.BoolVar(&quiet, "quiet", false, "suppress per-project progress logs")
	fs.StringVar(&fmtFlag, "format", "json", "report format: json or markdown")
	fs.BoolVar(&autoCorpus, "autocorpus", false, "clone the curated benchmark corpus into a temp directory and scan that instead of --corpus")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	if autoCorpus {
		dir, err := materialiseAutoCorpus(quiet)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: materialising autocorpus: %v\n", err)
			return 2
		}
		corpusDir = dir
	}

	entries, err := os.ReadDir(corpusDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: reading corpus dir %s: %v\n", corpusDir, err)
		return 2
	}

	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: locating nox binary: %v\n", err)
		return 2
	}

	report := BenchReport{
		StartedAt:  time.Now().UTC().Format(time.RFC3339),
		NoxBinary:  exe,
		NoxVersion: version,
	}

	// Which upstream ref each cloned directory holds, for --autocorpus.
	pins := map[string]struct{ Repo, Ref string }{}
	for _, entry := range curatedAutoCorpus {
		owner, repo := splitRepoSlug(entry.Repo)
		if owner == "" {
			continue
		}
		pins[owner+"--"+repo] = struct{ Repo, Ref string }{entry.Repo, entry.Ref}
	}

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		project := filepath.Join(corpusDir, e.Name())
		if !quiet {
			fmt.Fprintf(os.Stderr, "[bench] scanning %s\n", project)
		}
		summary, err := scanProject(exe, project)
		if err != nil {
			report.Failed = append(report.Failed, FailedProject{Path: project, Error: err.Error()})
			continue
		}
		if pin, ok := pins[e.Name()]; ok {
			summary.Repo, summary.Ref = pin.Repo, pin.Ref
		}
		// Resolved from the tree actually scanned, so it is right for a
		// hand-assembled --corpus too, and pins a moving tag to one commit.
		summary.Commit = gitHeadSHA(project)
		report.Projects = append(report.Projects, summary)
	}

	report.FinishedAt = time.Now().UTC().Format(time.RFC3339)
	aggregateRuleFireRates(&report)

	var out []byte
	switch fmtFlag {
	case "json":
		out, err = json.MarshalIndent(report, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: marshalling report: %v\n", err)
			return 2
		}
	case "markdown":
		out = []byte(renderBenchMarkdown(&report))
	default:
		fmt.Fprintf(os.Stderr, "error: unknown format %q\n", fmtFlag)
		return 2
	}

	if output == "" {
		fmt.Println(string(out))
		return 0
	}
	if err := os.WriteFile(output, out, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "error: writing %s: %v\n", output, err)
		return 2
	}
	if !quiet {
		fmt.Fprintf(os.Stderr, "[bench] wrote %s (%d projects)\n", output, len(report.Projects))
	}
	return 0
}

// BenchReport is the top-level bench output. Stable JSON shape so
// downstream tooling can join across runs.
type BenchReport struct {
	StartedAt  string `json:"started_at"`
	FinishedAt string `json:"finished_at"`
	NoxBinary  string `json:"nox_binary"`
	// NoxVersion is the engine that produced these numbers.
	//
	// Without it a fire-rate report is uninterpretable the moment the engine
	// moves on, and it will be read anyway. The 2026-Q2 run recorded neither
	// this nor a commit per project; four months later its numbers were quoted
	// as current and used to argue for work that had already shipped -- the
	// character-bounded proximity fix, which is the single largest change to
	// these counts there has ever been. A benchmark that cannot say which
	// engine it measured is evidence for whatever the reader already believes.
	NoxVersion   string           `json:"nox_version"`
	Projects     []ProjectSummary `json:"projects"`
	Failed       []FailedProject  `json:"failed,omitempty"`
	RuleFireRate map[string]int   `json:"rule_fire_rate,omitempty"`
	// RulePrevalence carries findings, repos and collapsed sites together.
	// Ranking on findings alone ranks the corpus, not the rule.
	RulePrevalence map[string]*RulePrevalence `json:"rule_prevalence,omitempty"`
}

type ProjectSummary struct {
	Path string `json:"path"`
	// Repo, Ref and Commit identify WHAT was scanned. Path alone is a temp
	// directory that no longer exists by the time anyone reads the report.
	Repo     string         `json:"repo,omitempty"`
	Ref      string         `json:"ref,omitempty"`
	Commit   string         `json:"commit,omitempty"`
	Findings int            `json:"findings"`
	Duration string         `json:"duration"`
	ByRule   map[string]int `json:"by_rule"`
	// BySite counts DISTINCT sites per rule, after collapsing the locale and
	// version segments of a path. A documentation page carried in four
	// languages across two released versions is one condition an author can
	// fix, not eight, and raw counts rank it as eight.
	BySite map[string]int `json:"by_site"`
	// BySubject counts DISTINCT SUBJECTS per rule -- tier 3. Present only for
	// rules that DECLARE what their finding is about (rules.SubjectKindKey); a
	// rule that has not said does not get a guess, and its entry is absent
	// rather than zero, so "no subjects" and "not declared" stay distinguishable.
	BySubject map[string]int `json:"by_subject,omitempty"`
	BySev     map[string]int `json:"by_severity"`
}

type FailedProject struct {
	Path  string `json:"path"`
	Error string `json:"error"`
}

func scanProject(noxPath, project string) (ProjectSummary, error) {
	tmpOut, err := os.MkdirTemp("", "nox-bench-*")
	if err != nil {
		return ProjectSummary{}, err
	}
	defer os.RemoveAll(tmpOut) //nolint:errcheck // best-effort cleanup

	start := time.Now()
	cmd := exec.Command(noxPath, "scan", project, "--output", tmpOut, "--quiet")
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		// nox returns 1 on findings — treat that as success here. We
		// only care about scan errors.
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
			return ProjectSummary{}, err
		}
	}
	duration := time.Since(start).Round(time.Millisecond)

	raw, err := os.ReadFile(filepath.Join(tmpOut, "findings.json"))
	if err != nil {
		return ProjectSummary{}, err
	}
	var doc struct {
		Findings []findings.Finding `json:"findings"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return ProjectSummary{}, err
	}

	byRule := map[string]int{}
	bySev := map[string]int{}
	sites := map[string]map[string]struct{}{}
	// Tier 3. Keyed on (normalised path, subject) because a subject is
	// FILE-LOCAL: `- name: geerlingguy.apache` unpinned in two requirements.yml
	// files is two pins to add, and keying on the subject alone reported
	// IAC-211's 65 findings as 26 conditions for exactly that reason.
	subjects := map[string]map[string]struct{}{}
	for i := range doc.Findings {
		f := &doc.Findings[i]
		byRule[f.RuleID]++
		bySev[string(f.Severity)]++
		key := fmt.Sprintf("%s:%d", normaliseSitePath(f.Location.FilePath), f.Location.StartLine)
		if sites[f.RuleID] == nil {
			sites[f.RuleID] = map[string]struct{}{}
		}
		sites[f.RuleID][key] = struct{}{}
		if sub := f.Metadata["subject_id"]; sub != "" {
			if subjects[f.RuleID] == nil {
				subjects[f.RuleID] = map[string]struct{}{}
			}
			subjects[f.RuleID][normaliseSitePath(f.Location.FilePath)+"\x00"+sub] = struct{}{}
		}
	}
	bySite := make(map[string]int, len(sites))
	for rule, set := range sites {
		bySite[rule] = len(set)
	}
	bySubject := make(map[string]int, len(subjects))
	for rule, set := range subjects {
		bySubject[rule] = len(set)
	}

	return ProjectSummary{
		Path:      project,
		Findings:  len(doc.Findings),
		Duration:  duration.String(),
		ByRule:    byRule,
		BySite:    bySite,
		BySubject: bySubject,
		BySev:     bySev,
	}, nil
}

// aggregateRuleFireRates fills RuleFireRate with the count of unique
// projects in which each rule fired at least once. Operators use this
// to decide which rules carry their weight (high count = signal) vs
// which fire universally and should be downgraded (every project = noise).
func aggregateRuleFireRates(report *BenchReport) {
	counts := map[string]int{}
	prev := map[string]*RulePrevalence{}
	for i := range report.Projects {
		for rule, n := range report.Projects[i].ByRule {
			counts[rule]++
			p := prev[rule]
			if p == nil {
				p = &RulePrevalence{}
				prev[rule] = p
			}
			p.Repos++
			p.Findings += n
			p.Sites += report.Projects[i].BySite[rule]
			p.Subjects += report.Projects[i].BySubject[rule]
		}
	}
	report.RuleFireRate = counts
	report.RulePrevalence = prev
}

// RulePrevalence is the three numbers a rule has to be judged on together.
//
// Raw findings measure user-visible noise and nothing else: they are a property
// of the corpus as much as of the rule. Measured here, crewAI carries its
// documentation in four languages across two released versions, so one matched
// line in one page counts eight times, and a docs-matching rule outranks a
// rule that fires once in every repository scanned.
//
// So three numbers, and they answer different questions:
//
//	Findings  how much output an operator sees          (noise)
//	Repos     in how many projects the rule fires at all (prevalence)
//	Sites     distinct conditions, locale/version copies collapsed
//
// A rule with high Findings and Repos of 1 is one repository's shape. A rule
// with Repos across the corpus and few Sites each is a broad, quiet rule. Only
// the pair tells you which detector is worst on real software; neither number
// does it alone.
type RulePrevalence struct {
	Repos    int `json:"repos"`
	Findings int `json:"findings"`
	Sites    int `json:"sites"`
	// Subjects is tier 3, and is 0 for a rule that has not declared what its
	// finding is about. Zero therefore means "not declared", not "none found":
	// a rule with findings always has at least one subject once it declares.
	Subjects int `json:"subjects,omitempty"`
}

// docLocales is a LIST, not a shape.
//
// The shape `^[a-z]{2}(-[A-Za-z]{2,4})?$` was tried first and collapsed `ui`,
// `db`, `io` and `ai-ml` -- ordinary source directories -- because it describes
// the form of a language tag rather than membership of the set. `io` is even a
// real tag (Ido), so no refinement of the shape separates it from `pkg/io`.
// Language tags are a closed set; a list is the correct resolution and an
// over-collapse here would silently under-count a rule.
var docLocales = map[string]bool{
	"en": true, "es": true, "fr": true, "de": true, "it": true, "pt": true,
	"pt-BR": true, "pt-PT": true, "ru": true, "ja": true, "ko": true,
	"zh": true, "zh-Hans": true, "zh-Hant": true, "zh-CN": true, "zh-TW": true,
	"ar": true, "hi": true, "tr": true, "nl": true, "pl": true, "vi": true,
	"th": true, "id": true, "cs": true, "sv": true, "da": true, "fi": true,
	"he": true, "uk": true, "ro": true, "hu": true, "el": true, "fa": true,
	"bn": true, "ms": true, "nb": true, "sk": true, "bg": true, "hr": true,
	"en-US": true, "en-GB": true, "es-ES": true, "fr-FR": true, "de-DE": true,
}

// versionSegment matches a released-docs directory: `v1.14.4`, `1.10.0`,
// `edge`, `latest`, `stable`.
//
// `main` and `next` are deliberately absent. Both are ordinary directory names
// -- `src/main/java` in every Maven project, `next` in a Next.js tree -- and
// collapsing them would merge unrelated files.
var versionSegment = regexp.MustCompile(`^(?:v?\d+(?:\.\d+){1,3}|edge|latest|stable)$`)

// normaliseSitePath collapses the locale and version directories that make one
// authored line appear as many.
//
// It drops only a segment that is a known documentation locale or a version,
// so `docs/edge/ko/tools/x.mdx` and `docs/v1.14.4/en/tools/x.mdx` become the
// same site while `src/ui`, `internal/db` and `pkg/io` are untouched. Erring
// towards keeping a segment costs a little collapse; erring the other way
// under-counts a rule, which is the direction that hides a problem.
func normaliseSitePath(p string) string {
	parts := strings.Split(filepath.ToSlash(p), "/")
	kept := parts[:0]
	for _, seg := range parts {
		if docLocales[seg] || versionSegment.MatchString(seg) {
			continue
		}
		kept = append(kept, seg)
	}
	if len(kept) == 0 {
		return p
	}
	return strings.Join(kept, "/")
}

// renderPrevalence prints the tiers of counting side by side, because reading
// any one of them alone has already produced a wrong conclusion here.
//
// Tier 1, RAW FINDINGS, is what an operator sees and is a property of the
// corpus as much as of the rule. Tier 2, AUTHORED OCCURRENCES, collapses the
// locale and version copies of one file, so a line someone actually wrote is
// counted once. The distance between them is not a detail: AI-029 measured
// 446 raw findings on crewAI and 26 authored occurrences, and the raw number
// ranked it among the worst rules in the set while the authored number showed
// it was one documentation page.
//
// Tier 3, DISTINCT SECURITY CONDITIONS, is counted for rules that DECLARE what
// their finding is about (rules.SubjectKindKey) and printed as `not declared`
// for the rest -- never as 0, so "none found" and "never asked" stay apart.
//
// It is declared and not derived because no location-derived definition is
// right for both measured cases: IAC-211's three unpinned roles in one block
// are three pins, and two tuning parameters on consecutive lines are one
// decision. A construct-keyed subject merges the first, a value-keyed subject
// splits the second. See docs/design/condition-dedup.md.
//
// The keying is on (path, subject) because a subject is FILE-LOCAL. Keyed on
// the subject alone, IAC-211's 65 findings read as 26 conditions -- the same
// role is unpinned in several requirements.yml files, and each is its own pin.
//
// The history below is kept because it is why this is a declaration rather
// than a heuristic. Nothing already in the tree carried the identity:
//
//   - Fingerprints cannot do it. V2 hashes rule ID, normalised path and the
//     MATCHED CONTENT (core/findings/fingerprint.go). It drops the line number,
//     so it already collapses a value that moved -- but two different matched
//     strings hash differently by construction, and the two penalty lines are
//     two different strings. Collapsing them would mean a fingerprint that is
//     not a function of what matched, which is the one property baselines and
//     waivers depend on.
//   - `structural_claim` is the only subject-like field a finding carries, and
//     it is IaC-only: set in core/analyzers/iac/iac.go and nowhere else. It
//     names a parsed resource ("the cloudformation resource \"LogBucket\"").
//     The obvious cheap implementation is to count distinct claims per rule and
//     call that tier 3. Measured on geerlingguy/ansible-for-devops before
//     writing it: 17 of 245 findings carry a claim at all (7%), and for every
//     rule that has one the count of claims EQUALS the count of findings --
//     IAC-139 is 6 findings over 6 subjects, IAC-140 the same. It collapses
//     nothing. A tier-3 column built on it would be blank for 93% of findings
//     and a copy of tier 1 for the rest: something that looks like a
//     measurement and measures nothing, which is worse than the honest blank.
//   - core/lexctx classifies regions as code, comment, string or data blob
//     across 21 languages, and ident.go is byte predicates. Neither yields a
//     named construct.
//
// So tier 3 needs a notion of SUBJECT that spans analyzers -- the thing a
// finding is about, as distinct from where it was found -- and that is a design
// change, not a reporting one.
//
// Half of it is already specified: docs/design/condition-dedup.md proposes a
// `condition` key on rules, and enumerates the 16 same-span pairs that must end
// up with DIFFERENT conditions. That answers "which rules report the same
// thing". It does not answer this one: within a single rule the condition is
// constant, so counting it returns 1 every time. Tier 3 is condition x subject,
// and the subject half is the part nothing in the tree carries.
//
// What is deliberately NOT done here: collapsing by proximity. "Same rule, same
// file, within N lines" would merge the two penalty lines correctly and merge
// two genuinely distinct credentials on adjacent lines just as happily, and a
// count that is sometimes conditions and sometimes not is worse than a count
// that is honestly occurrences.
func renderPrevalence(b *strings.Builder, report *BenchReport) {
	if len(report.RulePrevalence) == 0 {
		return
	}
	b.WriteString("\n## Rule prevalence\n\n")
	b.WriteString("Raw findings are what an operator sees. Authored occurrences collapse the\n")
	b.WriteString("locale and version copies of a file, so one written line counts once.\n")
	b.WriteString("Distinct security conditions are counted only for rules that DECLARE what their\n")
	b.WriteString("finding is about; the rest read `not declared`. See renderPrevalence.\n\n")

	type row struct {
		rule                             string
		repos, findings, sites, subjects int
	}
	rows := make([]row, 0, len(report.RulePrevalence))
	for r, p := range report.RulePrevalence {
		rows = append(rows, row{r, p.Repos, p.Findings, p.Sites, p.Subjects})
	}
	// Ranked by authored occurrences, then by repos: the pair that says which
	// detector is actually worst on real software.
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].sites != rows[j].sites {
			return rows[i].sites > rows[j].sites
		}
		if rows[i].repos != rows[j].repos {
			return rows[i].repos > rows[j].repos
		}
		return rows[i].rule < rows[j].rule
	})
	b.WriteString("| Rule | Repos | Raw findings | Authored occurrences | Copy factor | Distinct conditions |\n")
	b.WriteString("|---|---|---|---|---|---|\n")
	for _, r := range rows {
		factor := "—"
		if r.sites > 0 && r.findings > r.sites {
			factor = fmt.Sprintf("%.1fx", float64(r.findings)/float64(r.sites))
		}
		conditions := "not declared"
		if r.subjects > 0 {
			conditions = fmt.Sprintf("%d", r.subjects)
		}
		fmt.Fprintf(b, "| %s | %d | %d | %d | %s | %s |\n",
			r.rule, r.repos, r.findings, r.sites, factor, conditions)
	}
}

func renderBenchMarkdown(report *BenchReport) string {
	var b strings.Builder
	b.WriteString("# Nox bench report\n\n")
	fmt.Fprintf(&b, "- Started: %s\n", report.StartedAt)
	fmt.Fprintf(&b, "- Finished: %s\n", report.FinishedAt)
	fmt.Fprintf(&b, "- Projects scanned: %d (failed: %d)\n\n", len(report.Projects), len(report.Failed))

	b.WriteString("## Per-project summary\n\n")
	b.WriteString("| Project | Findings | Duration |\n|---|---|---|\n")
	for i := range report.Projects {
		p := &report.Projects[i]
		fmt.Fprintf(&b, "| %s | %d | %s |\n", p.Path, p.Findings, p.Duration)
	}
	b.WriteString("\n")

	b.WriteString("## Rule fire-rate (number of projects each rule fired in)\n\n")
	type kv struct {
		rule  string
		count int
	}
	var pairs []kv
	for r, c := range report.RuleFireRate {
		pairs = append(pairs, kv{r, c})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].count != pairs[j].count {
			return pairs[i].count > pairs[j].count
		}
		return pairs[i].rule < pairs[j].rule
	})
	b.WriteString("| Rule | Projects |\n|---|---|\n")
	for _, p := range pairs {
		fmt.Fprintf(&b, "| %s | %d |\n", p.rule, p.count)
	}
	renderPrevalence(&b, report)

	if len(report.Failed) > 0 {
		b.WriteString("\n## Failed projects\n\n")
		for _, f := range report.Failed {
			fmt.Fprintf(&b, "- `%s` — %s\n", f.Path, f.Error)
		}
	}
	return b.String()
}

// materialiseAutoCorpus clones every entry in curatedAutoCorpus into
// a fresh temp directory and returns its path. Repos already present
// from a previous run are skipped (the temp dir is unique per
// invocation, so this only matters when callers pass the same
// directory twice — operators don't, but bench tests do).
func materialiseAutoCorpus(quiet bool) (string, error) {
	dir, err := os.MkdirTemp("", "nox-bench-autocorpus-*")
	if err != nil {
		return "", err
	}
	for _, entry := range curatedAutoCorpus {
		owner, repo := splitRepoSlug(entry.Repo)
		if owner == "" {
			continue
		}
		dest := filepath.Join(dir, owner+"--"+repo)
		if !quiet {
			fmt.Fprintf(os.Stderr, "[bench] cloning %s@%s\n", entry.Repo, entry.Ref)
		}
		cmd := exec.Command("git", "clone", "--depth", "1",
			"--branch", entry.Ref,
			"https://github.com/"+entry.Repo+".git",
			dest)
		out, err := cmd.CombinedOutput()
		if err != nil {
			fmt.Fprintf(os.Stderr, "[bench] skipping %s: %v\n%s\n", entry.Repo, err, out)
			continue
		}
	}
	return dir, nil
}

// gitHeadSHA returns the commit a scanned tree is at, or "" when it is not a
// git checkout. Best-effort by design: a corpus directory need not be a repo,
// and an unidentifiable project is worth reporting without its SHA.
func gitHeadSHA(dir string) string {
	out, err := exec.Command("git", "-C", dir, "rev-parse", "HEAD").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func splitRepoSlug(slug string) (owner, repo string) {
	for i := 0; i < len(slug); i++ {
		if slug[i] == '/' {
			return slug[:i], slug[i+1:]
		}
	}
	return "", slug
}
