package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// A before/after pair, scanned end to end through the CLI: testdata/false-
// allclear/hardened is a hardened application, insecure is the same
// application after a "just for debugging" commit that opens it up. Every
// change in the second is something a reviewer should be told about, and the
// scanner used to say exactly what it said about the first.
//
// The pair exists because a rule fixture proves a pattern, not an outcome. What
// matters is the DIFFERENCE between the two scans: a rule that fires on both
// teaches people to ignore it, and a rule that fires on neither is a scanner
// reporting nothing.

func scanFalseAllClear(t *testing.T, tree string) (map[string]int, inventoryToolMatrix) {
	t.Helper()
	out := t.TempDir()
	src := filepath.Join("..", "testdata", "false-allclear", tree)
	var code int
	stdout := captureStdout(t, func() {
		code = run([]string{"scan", "--no-cache", "--offline", "--output", out, src})
	})
	if code != 0 && code != 1 {
		t.Fatalf("scan %s exit %d\n%s", tree, code, stdout)
	}
	var report struct {
		Findings []struct {
			RuleID string
		}
	}
	data, err := os.ReadFile(filepath.Join(out, "findings.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, f := range report.Findings {
		counts[f.RuleID]++
	}
	var inv inventoryToolMatrix
	data, err = os.ReadFile(filepath.Join(out, "ai.inventory.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &inv); err != nil {
		t.Fatal(err)
	}
	return counts, inv
}

type inventoryToolMatrix struct {
	ToolPermissionMatrix []struct {
		Tools        []string            `json:"tools"`
		Capabilities map[string][]string `json:"capabilities"`
	} `json:"tool_permission_matrix"`
}

func (m inventoryToolMatrix) capabilities(tool string) []string {
	var caps []string
	for _, set := range m.ToolPermissionMatrix {
		caps = append(caps, set.Capabilities[tool]...)
	}
	sort.Strings(caps)
	return caps
}

func TestFalseAllClear_InsecureChangesAreReportedAndHardenedNoiseIsGone(t *testing.T) {
	hardened, hardenedInv := scanFalseAllClear(t, "hardened")
	insecure, insecureInv := scanFalseAllClear(t, "insecure")

	// Each insecure change, and the rule that must now say so. None of these
	// may appear on the hardened side.
	for _, c := range []struct{ rule, change string }{
		{"MCP-002", "filesystem MCP server rooted at /"},
		{"MCP-003", "MCP server env switched to ALLOW_ALL=1"},
		{"MCP-025", "MCP servers launched from the registry with no version"},
		{"IAC-502", "DATABASE_PASSWORD moved from secretKeyRef to a literal value"},
		{"IAC-503", "compose DB_PASSWORD written as a literal"},
		{"IAC-504", "S3 public access block switched off"},
		{"IAC-302", "capabilities.add: [SYS_ADMIN] replacing drop: [ALL]"},
		{"IAC-149", "Ingress tls block removed"},
		{"AI-AGENT-009", "tool that executes model-supplied SQL"},
	} {
		if insecure[c.rule] == 0 {
			t.Errorf("%s did not fire on the insecure tree: %s", c.rule, c.change)
		}
		if hardened[c.rule] != 0 {
			t.Errorf("%s fired %d times on the hardened tree, which has no such change", c.rule, hardened[c.rule])
		}
	}

	// Noise the hardened tree used to produce, and must not.
	for _, c := range []struct{ rule, why string }{
		{"IAC-135", "seccompProfile RuntimeDefault is set at pod level and inherited"},
		{"IAC-296", "the Ingress has a tls block (rule retired into IAC-149)"},
		{"IAC-144", "a single key from a Secret via secretKeyRef is the recommended form"},
	} {
		if hardened[c.rule] != 0 {
			t.Errorf("%s fired on the hardened tree: %s", c.rule, c.why)
		}
		if insecure[c.rule] != 0 {
			t.Errorf("%s fired on the insecure tree, whose seccomp, Ingress and Secret use did not change shape: %s", c.rule, c.why)
		}
	}

	// The inventory says what the tool can do, not just that it exists.
	if got := strings.Join(insecureInv.capabilities("query_db"), ","); !strings.Contains(got, "sql_exec") {
		t.Errorf("insecure tool_permission_matrix: query_db capabilities = %q, want sql_exec", got)
	}
	if got := hardenedInv.capabilities("get_invoice"); len(got) != 0 {
		t.Errorf("hardened tool_permission_matrix: get_invoice capabilities = %v, want none", got)
	}
}
