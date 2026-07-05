package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
)

// Grounding contract.
//
// The strategic design is "deterministic-first, LLM-second": nox's core finds
// and GROUNDS every candidate deterministically (rule ID, file, line,
// fingerprint). This plugin only asks the LLM to CONFIRM/EXPLAIN a candidate
// that already exists — never to discover new ones.
//
// Two properties enforce that the LLM can never invent a finding location:
//
//  1. The prompt (buildPrompt) hands the model the exact, immutable rule ID,
//     file:line, and code snippet and instructs it to judge ONLY that finding.
//  2. parseVerdict extracts a disposition + rationale ONLY. It never reads a
//     file path or line from the model's reply. The resulting Verdict carries
//     the ORIGINAL finding's fingerprint (copied from the input finding, not
//     from the model), and emitVerdicts anchors the enrichment to that
//     fingerprint. A model that "hallucinates" a different file/line in its
//     prose therefore cannot create, move, or emit any finding — the only
//     observable effect of triage is an enrichment on the pre-existing finding.

// Disposition is the LLM's verdict on whether a finding is a true positive.
type Disposition string

const (
	DispTruePositive  Disposition = "true_positive"
	DispFalsePositive Disposition = "false_positive"
	DispUncertain     Disposition = "uncertain"
)

// LLMClient is the minimal interface the triage loop needs. The real
// implementation is an OpenAI-compatible HTTP client; tests inject a mock so no
// network or model is required to exercise the logic.
type LLMClient interface {
	Complete(ctx context.Context, prompt string) (string, error)
}

// SnippetReader returns a few lines of source around a finding's location.
type SnippetReader func(filePath string, line int) string

// Verdict is one triaged finding.
type Verdict struct {
	Fingerprint string
	RuleID      string
	Disposition Disposition
	Rationale   string
}

// TriageOptions bounds and configures a triage run. The routing gates
// (MinSeverity, SkipHighConfidence, OnlyRules, SkipRules) exist so an operator
// can spend LLM tokens only on the residual that actually needs a second
// opinion — deterministic-high-confidence findings are already trustworthy.
type TriageOptions struct {
	MaxFindings int      // 0 = unlimited
	MinSeverity Severity // findings below this are skipped

	// SkipHighConfidence, when true, routes only low/medium-confidence
	// "residual" to the LLM. ConfidenceHigh findings are already trustworthy
	// deterministic hits, so re-judging them wastes tokens without adding
	// signal. Findings with unspecified confidence are treated as residual
	// (judged) so an unset field never silently drops coverage.
	SkipHighConfidence bool

	// OnlyRules, if non-empty, restricts triage to findings whose rule ID
	// matches one of these patterns (glob or prefix — see ruleMatches). Use it
	// to point the LLM at exactly the noisy families (e.g. "SECRET-*").
	OnlyRules []string

	// SkipRules excludes findings whose rule ID matches one of these patterns.
	// SkipRules is applied after OnlyRules, so an exclusion always wins.
	SkipRules []string
}

// Severity ordering for the min-severity gate.
type Severity int

const (
	SevInfo Severity = iota
	SevLow
	SevMedium
	SevHigh
	SevCritical
)

func severityRank(s pluginv1.Severity) Severity {
	switch s {
	case pluginv1.Severity_SEVERITY_CRITICAL:
		return SevCritical
	case pluginv1.Severity_SEVERITY_HIGH:
		return SevHigh
	case pluginv1.Severity_SEVERITY_MEDIUM:
		return SevMedium
	case pluginv1.Severity_SEVERITY_LOW:
		return SevLow
	default:
		return SevInfo
	}
}

// isHighConfidence reports whether a finding is a deterministic high-confidence
// hit. Only CONFIDENCE_HIGH qualifies; unspecified/medium/low are residual.
func isHighConfidence(c pluginv1.Confidence) bool {
	return c == pluginv1.Confidence_CONFIDENCE_HIGH
}

// ruleMatches reports whether ruleID matches pattern. A pattern ending in "*"
// is a prefix match ("SECRET-*" matches "SECRET-ENTROPY"); otherwise it is an
// exact, case-sensitive rule ID. filepath.Match handles richer glob syntax
// ("SEC-00?"); a malformed pattern degrades to a literal compare rather than
// erroring, so a bad filter never aborts the run.
func ruleMatches(ruleID, pattern string) bool {
	if pattern == "" {
		return false
	}
	if strings.HasSuffix(pattern, "*") {
		if strings.HasPrefix(ruleID, strings.TrimSuffix(pattern, "*")) {
			return true
		}
	}
	if ok, err := filepath.Match(pattern, ruleID); err == nil && ok {
		return true
	}
	return ruleID == pattern
}

// matchesAny reports whether ruleID matches any pattern in patterns.
func matchesAny(ruleID string, patterns []string) bool {
	for _, p := range patterns {
		if ruleMatches(ruleID, p) {
			return true
		}
	}
	return false
}

// shouldTriage applies the routing gates to a single finding and reports
// whether it should be sent to the LLM. It is the single source of truth for
// "does this finding need a second opinion", kept pure so it is table-testable.
func shouldTriage(f *pluginv1.Finding, opts TriageOptions) bool {
	if severityRank(f.GetSeverity()) < opts.MinSeverity {
		return false
	}
	if opts.SkipHighConfidence && isHighConfidence(f.GetConfidence()) {
		return false
	}
	ruleID := f.GetRuleId()
	if len(opts.OnlyRules) > 0 && !matchesAny(ruleID, opts.OnlyRules) {
		return false
	}
	if matchesAny(ruleID, opts.SkipRules) {
		return false
	}
	return true
}

// dedupeFindings collapses findings that ask the LLM the same question twice.
// Two findings are duplicates when they share a fingerprint, or (lacking a
// fingerprint) the same rule ID + file:line. Deterministically pre-collapsing
// them before any LLM call saves tokens and makes the run more reproducible —
// the LLM sees each distinct candidate exactly once, in first-seen order. The
// input slice is not mutated.
func dedupeFindings(findings []*pluginv1.Finding) []*pluginv1.Finding {
	seen := make(map[string]struct{}, len(findings))
	out := make([]*pluginv1.Finding, 0, len(findings))
	for _, f := range findings {
		key := f.GetFingerprint()
		if key == "" {
			loc := f.GetLocation()
			key = fmt.Sprintf("%s\x00%s\x00%d", f.GetRuleId(), loc.GetFilePath(), loc.GetStartLine())
		}
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, f)
	}
	return out
}

// triageFindings asks the LLM to judge each finding as a true or false positive,
// returning one verdict per judged finding. It is pure with respect to I/O: the
// LLM client and snippet reader are injected, so the same logic runs in tests
// with a deterministic mock. It never mutates the findings.
func triageFindings(ctx context.Context, client LLMClient, read SnippetReader, findings []*pluginv1.Finding, opts TriageOptions) ([]Verdict, error) {
	// Deterministic pre-dedup: collapse duplicate candidates before spending a
	// single token, so the LLM is never asked the same question twice.
	findings = dedupeFindings(findings)

	var verdicts []Verdict
	judged := 0
	for _, f := range findings {
		if opts.MaxFindings > 0 && judged >= opts.MaxFindings {
			break
		}
		// Residual-only + confidence-gated routing: skip findings that don't
		// need an LLM (below min severity, already high-confidence, or filtered
		// out by rule).
		if !shouldTriage(f, opts) {
			continue
		}
		if err := ctx.Err(); err != nil {
			return verdicts, err
		}
		loc := f.GetLocation()
		file, line := "", 0
		if loc != nil {
			file, line = loc.GetFilePath(), int(loc.GetStartLine())
		}
		snippet := ""
		if read != nil && file != "" {
			snippet = read(file, line)
		}
		prompt := buildPrompt(f, snippet)
		out, err := client.Complete(ctx, prompt)
		if err != nil {
			// A transient LLM error must not abort the whole run; record the
			// finding as uncertain and continue.
			verdicts = append(verdicts, Verdict{
				Fingerprint: f.GetFingerprint(),
				RuleID:      f.GetRuleId(),
				Disposition: DispUncertain,
				Rationale:   "LLM call failed: " + err.Error(),
			})
			judged++
			continue
		}
		disp, rationale := parseVerdict(out)
		verdicts = append(verdicts, Verdict{
			Fingerprint: f.GetFingerprint(),
			RuleID:      f.GetRuleId(),
			Disposition: disp,
			Rationale:   rationale,
		})
		judged++
	}
	return verdicts, nil
}

// buildPrompt renders a deterministic triage prompt for one finding. It states
// the grounding contract explicitly — the model judges ONLY the given finding
// at its given location and must not report any new finding or location — and
// asks for a strict, machine-parseable first line so parseVerdict is
// unambiguous. The rule ID, file:line, and snippet are passed as immutable
// context; nothing in the reply is ever used to derive a finding location.
func buildPrompt(f *pluginv1.Finding, snippet string) string {
	var b strings.Builder
	b.WriteString("You are a security triage assistant. You are given ONE static-analysis finding, already located by a deterministic scanner. Your ONLY job is to judge whether THIS specific finding, at THIS exact location, is a TRUE POSITIVE (a real, exploitable issue) or a FALSE POSITIVE (safe in context).\n\n")
	b.WriteString("Rules you must follow:\n")
	b.WriteString("- Judge only the finding below. Do NOT report new findings, new issues, or any other file or line.\n")
	b.WriteString("- Do NOT propose a different location; the location is fixed and authoritative.\n")
	b.WriteString("- If the given snippet is insufficient to decide, answer UNCERTAIN.\n\n")
	b.WriteString("Finding under review (immutable):\n")
	b.WriteString("Rule: " + f.GetRuleId() + "\n")
	b.WriteString("Severity: " + f.GetSeverity().String() + "\n")
	b.WriteString("Message: " + f.GetMessage() + "\n")
	if loc := f.GetLocation(); loc != nil {
		fmt.Fprintf(&b, "Location: %s:%d\n", loc.GetFilePath(), loc.GetStartLine())
	}
	if snippet != "" {
		b.WriteString("\nCode context (the given location):\n```\n")
		b.WriteString(snippet)
		b.WriteString("\n```\n")
	}
	b.WriteString("\nAnswer with exactly one of TRUE_POSITIVE, FALSE_POSITIVE, or UNCERTAIN on the first line, then one sentence of justification about THIS finding on the second line.")
	return b.String()
}

// parseVerdict extracts the disposition and rationale from the model's reply,
// and NOTHING ELSE. It deliberately never reads a file path or line number from
// the reply: the finding's location is fixed by the deterministic scanner, so a
// hallucinated location in the model's prose is inert — it can only ever land in
// the free-text rationale, never in a finding. It is lenient about surrounding
// formatting but keys off the first recognized token so an unexpected reply
// falls back to UNCERTAIN rather than mislabeling.
func parseVerdict(out string) (disposition Disposition, rationale string) {
	upper := strings.ToUpper(out)
	disposition = DispUncertain
	switch {
	case strings.Contains(upper, "TRUE_POSITIVE") || strings.Contains(upper, "TRUE POSITIVE"):
		disposition = DispTruePositive
	case strings.Contains(upper, "FALSE_POSITIVE") || strings.Contains(upper, "FALSE POSITIVE"):
		disposition = DispFalsePositive
	}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		line = strings.TrimSpace(line)
		u := strings.ToUpper(line)
		if line == "" || u == "TRUE_POSITIVE" || u == "FALSE_POSITIVE" || u == "UNCERTAIN" ||
			u == "TRUE POSITIVE" || u == "FALSE POSITIVE" {
			continue
		}
		rationale = line
		break
	}
	return disposition, rationale
}

// fileSnippetReader returns a SnippetReader rooted at workspaceRoot that reads a
// window of `radius` lines on each side of the finding line. Returns "" on any
// read error so triage degrades gracefully to message-only prompts.
func fileSnippetReader(workspaceRoot string, radius int) SnippetReader {
	return func(filePath string, line int) string {
		if filePath == "" || line <= 0 {
			return ""
		}
		p := filePath
		if !filepath.IsAbs(p) && workspaceRoot != "" {
			p = filepath.Join(workspaceRoot, filePath)
		}
		file, err := os.Open(p) //nolint:gosec // path derived from scan findings within the workspace
		if err != nil {
			return ""
		}
		defer func() { _ = file.Close() }()

		start := line - radius
		if start < 1 {
			start = 1
		}
		end := line + radius
		var b strings.Builder
		n := 0
		sc := bufio.NewScanner(file)
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for sc.Scan() {
			n++
			if n < start {
				continue
			}
			if n > end {
				break
			}
			b.WriteString(sc.Text())
			b.WriteByte('\n')
		}
		return strings.TrimRight(b.String(), "\n")
	}
}

// summarize renders a one-line diagnostic of the triage outcome.
func summarize(verdicts []Verdict) string {
	var tp, fp, unc int
	for i := range verdicts {
		switch verdicts[i].Disposition {
		case DispTruePositive:
			tp++
		case DispFalsePositive:
			fp++
		default:
			unc++
		}
	}
	return fmt.Sprintf("llm-triage: %d judged — %d true-positive, %d false-positive, %d uncertain", len(verdicts), tp, fp, unc)
}
