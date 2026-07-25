package mcpdrift

import (
	"fmt"
	"sort"
	"strings"

	"github.com/nox-hq/nox/core/findings"
)

// Rule IDs for MCP manifest drift. They live in the shared findings namespace so
// drift flows through findings.json / SARIF exactly like any other finding.
const (
	// RuleNewExecTool: a code-execution-capable tool appeared that did not exist
	// at review time. The highest-severity rug-pull outcome.
	RuleNewExecTool = "MCP-DRIFT-001"
	// RuleNewTool: a new tool appeared post-review (capability the reviewer never
	// approved).
	RuleNewTool = "MCP-DRIFT-002"
	// RuleRemovedTool: a tool disappeared. Lower severity, but still drift the
	// reviewer should see.
	RuleRemovedTool = "MCP-DRIFT-003"
	// RuleDescriptionChanged: an advertised description was mutated — the classic
	// rug-pull (benign at review, injected later).
	RuleDescriptionChanged = "MCP-DRIFT-004"
	// RuleSchemaWidened: a tool's input schema gained properties (possible
	// credential harvesting or capability expansion).
	RuleSchemaWidened = "MCP-DRIFT-005"
	// RuleSchemaChanged: a tool's input schema changed without widening.
	RuleSchemaChanged = "MCP-DRIFT-006"
)

// execIndicators are substrings that, in a tool name or description, suggest the
// tool can run code or shell commands. Used only to escalate a NEW tool from
// high to critical — a conservative bump, since a newly-appeared exec tool is
// the worst rug-pull outcome.
var execIndicators = []string{
	"exec", "execute", "eval", "shell", "command", "subprocess",
	"spawn", "run_command", "system(", "/bin/sh", "bash", "powershell",
	"code execution", "arbitrary code",
}

// looksCodeExecuting reports whether a tool's name or description suggests
// code/command execution.
func looksCodeExecuting(t Tool) bool {
	hay := strings.ToLower(t.Name + " " + t.Description)
	for _, ind := range execIndicators {
		if strings.Contains(hay, ind) {
			return true
		}
	}
	return false
}

// ToFindings maps a manifest diff to canonical findings. source is the baseline
// file path (used as the finding location so the drift anchors to a real,
// reviewable file in SARIF/GitHub). server labels the findings in messages and
// metadata. The returned slice is deterministically ordered.
func ToFindings(d Diff, source, server string) []findings.Finding {
	var out []findings.Finding

	loc := findings.Location{FilePath: source, StartLine: 1, EndLine: 1}

	for _, t := range d.AddedTools {
		rule := RuleNewTool
		sev := findings.SeverityHigh
		what := "a new tool"
		if looksCodeExecuting(t) {
			rule = RuleNewExecTool
			sev = findings.SeverityCritical
			what = "a new code-execution-capable tool"
		}
		msg := fmt.Sprintf("MCP drift on %s: %s %q appeared that was not in the reviewed baseline (possible rug-pull).", server, what, t.Name)
		out = append(out, newDriftFinding(rule, sev, findings.ConfidenceHigh, loc, msg, map[string]string{
			"server":      server,
			"tool":        t.Name,
			"change_type": "tool_added",
			"description": truncate(t.Description, 300),
		}))
	}

	for _, name := range d.RemovedTools {
		msg := fmt.Sprintf("MCP drift on %s: tool %q in the reviewed baseline is no longer advertised.", server, name)
		out = append(out, newDriftFinding(RuleRemovedTool, findings.SeverityMedium, findings.ConfidenceHigh, loc, msg, map[string]string{
			"server":      server,
			"tool":        name,
			"change_type": "tool_removed",
		}))
	}

	for _, c := range d.Changes {
		switch c.Type {
		case DescriptionChanged:
			sev := findings.SeverityHigh
			// A description that mutates INTO exec/secret-directive language is the
			// canonical poisoning rug-pull — escalate.
			if descriptionLooksPoisoned(c.After) && !descriptionLooksPoisoned(c.Before) {
				sev = findings.SeverityCritical
			}
			msg := fmt.Sprintf("MCP drift on %s: description of tool %q changed after review (rug-pull vector).", server, c.Tool)
			out = append(out, newDriftFinding(RuleDescriptionChanged, sev, findings.ConfidenceHigh, loc, msg, map[string]string{
				"server":      server,
				"tool":        c.Tool,
				"change_type": string(DescriptionChanged),
				"before":      truncate(c.Before, 300),
				"after":       truncate(c.After, 300),
			}))
		case SchemaWidened:
			msg := fmt.Sprintf("MCP drift on %s: input schema of tool %q widened — new field(s): %s.", server, c.Tool, strings.Join(c.AddedProps, ", "))
			out = append(out, newDriftFinding(RuleSchemaWidened, findings.SeverityHigh, findings.ConfidenceHigh, loc, msg, map[string]string{
				"server":      server,
				"tool":        c.Tool,
				"change_type": string(SchemaWidened),
				"added_props": strings.Join(c.AddedProps, ","),
			}))
		default: // SchemaChanged
			msg := fmt.Sprintf("MCP drift on %s: input schema of tool %q changed after review.", server, c.Tool)
			out = append(out, newDriftFinding(RuleSchemaChanged, findings.SeverityMedium, findings.ConfidenceMedium, loc, msg, map[string]string{
				"server":      server,
				"tool":        c.Tool,
				"change_type": string(SchemaChanged),
			}))
		}
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].RuleID != out[j].RuleID {
			return out[i].RuleID < out[j].RuleID
		}
		return out[i].Metadata["tool"] < out[j].Metadata["tool"]
	})
	return out
}

// secretDirectiveIndicators flag a description that instructs the assistant to
// read secrets or conceal behaviour — the payload of a poisoning rug-pull.
var secretDirectiveIndicators = []string{
	"id_rsa", ".ssh", "credentials", "secret", "token", "api_key", "api key",
	"password", "do not reveal", "do not tell", "silently", "without telling",
	"ignore previous", "ignore all previous",
}

func descriptionLooksPoisoned(desc string) bool {
	hay := strings.ToLower(desc)
	for _, ind := range secretDirectiveIndicators {
		if strings.Contains(hay, ind) {
			return true
		}
	}
	return false
}

func newDriftFinding(rule string, sev findings.Severity, conf findings.Confidence, loc findings.Location, msg string, meta map[string]string) findings.Finding {
	f := findings.NewFinding(rule, sev, conf, loc, msg)
	f.Metadata = meta
	return f
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
