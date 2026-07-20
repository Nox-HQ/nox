package plugin

import (
	"strings"
	"testing"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
)

// The redactor must cover the whole GitHub token family, not just ghp_/ghs_.
// gho_ (OAuth), ghu_ (user-to-server), ghr_ (refresh) and github_pat_
// (fine-grained PAT) are equally sensitive and travel the same free-text path.
func TestRedact_GitHubTokenFamily(t *testing.T) {
	r := NewRedactor()
	tokens := map[string]string{
		"ghp": "ghp_" + strings.Repeat("A", 36),
		"ghs": "ghs_" + strings.Repeat("B", 36),
		"gho": "gho_" + strings.Repeat("C", 36),
		"ghu": "ghu_" + strings.Repeat("D", 36),
		"ghr": "ghr_" + strings.Repeat("E", 36),
		"pat": "github_pat_" + strings.Repeat("F", 22),
	}
	for name, tok := range tokens {
		t.Run(name, func(t *testing.T) {
			resp := &pluginv1.InvokeToolResponse{
				Findings: []*pluginv1.Finding{{Message: "token leaked: " + tok}},
			}
			out, redacted := r.RedactResponse(resp)
			if !redacted {
				t.Fatalf("%s token was not redacted", name)
			}
			if strings.Contains(out.GetFindings()[0].GetMessage(), tok) {
				t.Errorf("%s token leaked through: %q", name, out.GetFindings()[0].GetMessage())
			}
		})
	}
}

// Secrets must not slip through plugin-controlled structured string fields.
// A plugin fully controls Location.FilePath, AIComponent.Name/Type/Path,
// Diagnostic.Source, and GraphNode.FilePath, all of which are copied into
// on-disk artifacts (SARIF, findings.json, ai.inventory.json).
func TestRedact_StructuredFields(t *testing.T) {
	r := NewRedactor()
	secret := "ghp_" + strings.Repeat("Z", 36)

	resp := &pluginv1.InvokeToolResponse{
		Findings: []*pluginv1.Finding{{
			Location: &pluginv1.Location{FilePath: "https://user:" + secret + "@host/x", StartLine: 42, EndColumn: 9},
		}},
		AiComponents: []*pluginv1.AIComponent{{
			Name: "n-" + secret, Type: "t-" + secret, Path: "p-" + secret,
		}},
		Diagnostics: []*pluginv1.Diagnostic{{Source: "src-" + secret}},
		Graphs: []*pluginv1.Graph{{
			Nodes: []*pluginv1.GraphNode{{Id: "n1", FilePath: "g-" + secret}},
		}},
	}

	out, redacted := r.RedactResponse(resp)
	if !redacted {
		t.Fatal("expected redaction across structured fields")
	}

	fields := map[string]string{
		"Location.FilePath":  out.GetFindings()[0].GetLocation().GetFilePath(),
		"AIComponent.Name":   out.GetAiComponents()[0].GetName(),
		"AIComponent.Type":   out.GetAiComponents()[0].GetType(),
		"AIComponent.Path":   out.GetAiComponents()[0].GetPath(),
		"Diagnostic.Source":  out.GetDiagnostics()[0].GetSource(),
		"GraphNode.FilePath": out.GetGraphs()[0].GetNodes()[0].GetFilePath(),
	}
	for name, v := range fields {
		if strings.Contains(v, secret) {
			t.Errorf("%s leaked the secret: %q", name, v)
		}
	}

	// Location's non-secret positional fields must survive redaction.
	loc := out.GetFindings()[0].GetLocation()
	if loc.GetStartLine() != 42 || loc.GetEndColumn() != 9 {
		t.Errorf("location positional fields dropped: startLine=%d endColumn=%d", loc.GetStartLine(), loc.GetEndColumn())
	}
}
