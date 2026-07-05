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

// TriageOptions bounds and configures a triage run.
type TriageOptions struct {
	MaxFindings int      // 0 = unlimited
	MinSeverity Severity // findings below this are skipped
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

// triageFindings asks the LLM to judge each finding as a true or false positive,
// returning one verdict per judged finding. It is pure with respect to I/O: the
// LLM client and snippet reader are injected, so the same logic runs in tests
// with a deterministic mock. It never mutates the findings.
func triageFindings(ctx context.Context, client LLMClient, read SnippetReader, findings []*pluginv1.Finding, opts TriageOptions) ([]Verdict, error) {
	var verdicts []Verdict
	judged := 0
	for _, f := range findings {
		if opts.MaxFindings > 0 && judged >= opts.MaxFindings {
			break
		}
		if severityRank(f.GetSeverity()) < opts.MinSeverity {
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

// buildPrompt renders a deterministic triage prompt for one finding. It asks for
// a strict, machine-parseable first line so parseVerdict is unambiguous.
func buildPrompt(f *pluginv1.Finding, snippet string) string {
	var b strings.Builder
	b.WriteString("You are a security triage assistant. Decide whether the following static-analysis finding is a TRUE POSITIVE (a real, exploitable issue) or a FALSE POSITIVE (safe in context).\n\n")
	b.WriteString("Rule: " + f.GetRuleId() + "\n")
	b.WriteString("Severity: " + f.GetSeverity().String() + "\n")
	b.WriteString("Message: " + f.GetMessage() + "\n")
	if loc := f.GetLocation(); loc != nil {
		fmt.Fprintf(&b, "Location: %s:%d\n", loc.GetFilePath(), loc.GetStartLine())
	}
	if snippet != "" {
		b.WriteString("\nCode context:\n```\n")
		b.WriteString(snippet)
		b.WriteString("\n```\n")
	}
	b.WriteString("\nAnswer with exactly one of TRUE_POSITIVE, FALSE_POSITIVE, or UNCERTAIN on the first line, then one sentence of justification on the second line.")
	return b.String()
}

// parseVerdict extracts the disposition and rationale from the model's reply.
// It is lenient about surrounding formatting but keys off the first recognized
// token so an unexpected reply falls back to UNCERTAIN rather than mislabeling.
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
