package server

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/nox-hq/nox/plugin"

	"github.com/nox-hq/nox/core/baseline"
	"github.com/nox-hq/nox/core/findings"
)

// An argument the server enforces has to be one a client can send. The published
// schema sets additionalProperties to false, so an argument missing from it is
// one a validating client strips or refuses to send: the gate would then refuse
// every call, and the only way through would be a client that does not validate.
func TestGatedToolsPublishTheirConsentArguments(t *testing.T) {
	srv := registeredServer(t, New("0.1.0", nil, WithPluginHost(plugin.NewHost())))
	want := map[string][]string{
		"baseline_add":      {"path", "fingerprint", "reason", "owner", "confirmed"},
		"baseline_add_many": {"path", "fingerprints", "reason", "owner", "confirmed"},
		"plugin_install":    {"name", "confirmed"},
	}
	for name, args := range want {
		tool, ok := srv.GetTool(name)
		if !ok {
			t.Errorf("tool %q is not registered", name)
			continue
		}
		raw, err := json.Marshal(tool.InputSchema())
		if err != nil {
			t.Fatalf("%s: marshalling the input schema: %v", name, err)
		}
		var schema struct {
			Properties map[string]json.RawMessage `json:"properties"`
		}
		if err := json.Unmarshal(raw, &schema); err != nil {
			t.Fatalf("%s: reading the input schema: %v", name, err)
		}
		for _, arg := range args {
			if _, ok := schema.Properties[arg]; !ok {
				t.Errorf("tool %q enforces %q but its schema does not declare it: %s", name, arg, raw)
			}
		}
	}
}

// scannedFinding scans a directory holding one finding and returns the server,
// the directory and the finding's fingerprint.
func scannedFinding(t *testing.T) (s *Server, dir, fingerprint string) {
	t.Helper()
	dir = t.TempDir()
	writeFile(t, dir, "config.env", "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n")
	s = New("0.1.0", nil)
	if out, err := s.handleScan(context.Background(), scanInput{Path: dir}); err != nil || strings.HasPrefix(out, "Error:") {
		t.Fatalf("scan failed: %v / %s", err, out)
	}
	active := s.getCache("").result.Findings.ActiveFindings()
	if len(active) == 0 {
		t.Fatal("the scan found nothing to baseline")
	}
	return s, dir, active[0].Fingerprint
}

func stillActive(s *Server, fingerprint string) bool {
	for _, f := range s.getCache("").result.Findings.ActiveFindings() {
		if f.Fingerprint == fingerprint {
			return true
		}
	}
	return false
}

// Adding a finding to the baseline stops nox reporting it. Both tools did that
// for any caller that asked: no reason, no consent, and an entry that said
// neither why nor that an agent wrote it. plugin_install already refused without
// `confirmed: true`; suppressing a finding is the other thing an agent should
// not be talked into doing on its own.
func TestBaselineTools_RefuseWithoutReasonOrConsent(t *testing.T) {
	type call struct {
		tool string
		args func(dir, fp string) map[string]any
	}
	calls := []call{
		{"baseline_add", func(dir, fp string) map[string]any {
			return map[string]any{"path": dir, "fingerprint": fp}
		}},
		{"baseline_add_many", func(dir, fp string) map[string]any {
			return map[string]any{"path": dir, "fingerprints": []string{fp}}
		}},
	}
	refusals := []struct {
		name     string
		extra    map[string]any
		wantSaid string
	}{
		{"no reason", map[string]any{"confirmed": true}, "requires a reason"},
		{"blank reason", map[string]any{"reason": "  \t", "confirmed": true}, "requires a reason"},
		{"no consent", map[string]any{"reason": "documented example key"}, "confirmed: true"},
		{"consent refused", map[string]any{"reason": "documented example key", "confirmed": false}, "confirmed: true"},
	}
	for _, c := range calls {
		for _, r := range refusals {
			t.Run(c.tool+"/"+r.name, func(t *testing.T) {
				s, dir, fp := scannedFinding(t)
				args := c.args(dir, fp)
				for k, v := range r.extra {
					args[k] = v
				}
				input, err := json.Marshal(args)
				if err != nil {
					t.Fatal(err)
				}
				got := executeTool(t, registeredServer(t, s), c.tool, string(input))
				if !got.isError {
					t.Errorf("the call was not refused: %q", got.text)
				}
				if !strings.Contains(got.text, r.wantSaid) {
					t.Errorf("the refusal %q does not say %q", got.text, r.wantSaid)
				}
				if _, err := os.Stat(baseline.DefaultPath(dir)); err == nil {
					t.Error("a refused call wrote a baseline file")
				}
				if !stillActive(s, fp) {
					t.Error("a refused call suppressed the finding in the cached results")
				}
			})
		}
	}
}

// What a granted call leaves behind is what a reviewer reads later: why the
// finding was accepted, who owns the decision, and that it came through the MCP
// server and not from a person at a terminal.
func TestBaselineTools_RecordWhyAndWhere(t *testing.T) {
	calls := map[string]func(dir, fp string) map[string]any{
		"baseline_add": func(dir, fp string) map[string]any {
			return map[string]any{"path": dir, "fingerprint": fp}
		},
		"baseline_add_many": func(dir, fp string) map[string]any {
			return map[string]any{"path": dir, "fingerprints": []string{fp}}
		},
	}
	for tool, build := range calls {
		t.Run(tool, func(t *testing.T) {
			s, dir, fp := scannedFinding(t)
			args := build(dir, fp)
			args["reason"] = "  AWS's documented example key  "
			args["owner"] = "platform"
			args["confirmed"] = true
			input, err := json.Marshal(args)
			if err != nil {
				t.Fatal(err)
			}
			got := executeTool(t, registeredServer(t, s), tool, string(input))
			if got.isError {
				t.Fatalf("the call was refused: %q", got.text)
			}

			bl, err := baseline.Load(baseline.DefaultPath(dir))
			if err != nil {
				t.Fatal(err)
			}
			if len(bl.Entries) != 1 {
				t.Fatalf("baseline holds %d entries, want 1", len(bl.Entries))
			}
			e := bl.Entries[0]
			if e.Fingerprint != fp {
				t.Errorf("entry fingerprint %q, want %q", e.Fingerprint, fp)
			}
			if e.Reason != "AWS's documented example key" {
				t.Errorf("entry reason %q, want the reason given, trimmed", e.Reason)
			}
			if e.Owner != "platform" {
				t.Errorf("entry owner %q, want platform", e.Owner)
			}
			if e.Source != baseline.SourceMCP {
				t.Errorf("entry source %q, want %q", e.Source, baseline.SourceMCP)
			}
			if stillActive(s, fp) {
				t.Error("the finding is still active in the cached results")
			}
			var status findings.Status
			for _, f := range s.getCache("").result.Findings.Findings() {
				if f.Fingerprint == fp {
					status = f.Status
				}
			}
			if status != findings.StatusBaselined {
				t.Errorf("cached status %q, want %q", status, findings.StatusBaselined)
			}
		})
	}
}
