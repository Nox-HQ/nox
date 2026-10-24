package core

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/nox-hq/nox/core/report/sbom"
)

// Same inputs, same outputs is the first design constraint, and it is a
// property of the bytes a scan writes, not of the findings alone. SARIF once
// carried a rule catalog built from a map iteration, so identical scans of one
// tree produced different results.sarif files while findings.json was stable;
// a test that compared findings would not have seen it.
//
// This scans one tree repeatedly, in one process, and renders every report the
// CLI writes, exactly as the CLI does (SARIF with the full rule catalog). Go
// re-randomizes map order on every range, so a map-order dependence anywhere on
// that path fails this with high probability; the specific defect it was
// written for is also pinned by order assertions in core/taint.
func TestScanReportsAreByteIdenticalAcrossRuns(t *testing.T) {
	// The report timestamp is the only input that legitimately changes
	// between runs; SOURCE_DATE_EPOCH pins it, as a reproducible build would.
	t.Setenv("SOURCE_DATE_EPOCH", "1700000000")

	dir := t.TempDir()
	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// A code_injection sink and an unsafe_deserialization sink: both report
	// TAINT-005, whose descriptor used to describe one or the other depending
	// on map order.
	write("app.py", "import pickle\nfrom flask import request\n\n"+
		"def run():\n    code = request.args.get('c')\n    eval(code)\n\n"+
		"def load():\n    blob = request.get_data()\n    return pickle.loads(blob)\n")
	// Enough for the AI inventory and the SBOMs to have something to order.
	write("agent.py", "from openai import OpenAI\nclient = OpenAI()\n"+
		"def ask(q):\n    return client.chat.completions.create(model='gpt-4o', messages=[{'role': 'user', 'content': q}])\n")
	write("requirements.txt", "flask==2.0.0\nopenai==1.3.0\n")
	write(".mcp.json", `{"mcpServers": {"fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/"]}}}`)

	render := func() map[string][]byte {
		t.Helper()
		result, err := RunScanWithOptions(dir, ScanOptions{Offline: true, DisableOSV: true})
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		out := map[string][]byte{}
		add := func(name string, b []byte, err error) {
			t.Helper()
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			out[name] = b
		}
		b, err := result.JSONReporter("test").Generate(result.Findings)
		add("findings.json", b, err)
		sr := result.SARIFReporter("test")
		sr.Rules = result.Rules
		b, err = sr.Generate(result.Findings)
		add("results.sarif", b, err)
		b, err = sbom.NewCycloneDXReporter("test").Generate(result.Inventory)
		add("sbom.cdx.json", b, err)
		b, err = sbom.NewSPDXReporter("test").Generate(result.Inventory)
		add("sbom.spdx.json", b, err)
		b, err = result.HTMLReporter("test").Generate(result.Findings)
		add("report.html", b, err)
		b, err = result.AIInventory.JSON()
		add("ai.inventory.json", b, err)
		return out
	}

	first := render()
	if !bytes.Contains(first["results.sarif"], []byte(`"TAINT-005"`)) {
		t.Fatal("the SARIF catalog has no TAINT-005 descriptor; the tree no longer exercises the shared rule ID")
	}
	const runs = 20
	for i := 2; i <= runs; i++ {
		for name, got := range render() {
			if !bytes.Equal(got, first[name]) {
				t.Errorf("run %d: %s differs from run 1 on the same tree", i, name)
			}
		}
	}
}
