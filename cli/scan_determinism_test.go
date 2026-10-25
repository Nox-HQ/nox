package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// SOURCE_DATE_EPOCH must be findable where a user looks for it.
func TestScanHelpDocumentsSourceDateEpoch(t *testing.T) {
	var buf bytes.Buffer
	printScanEnvironment(&buf)
	for _, want := range []string{"SOURCE_DATE_EPOCH", "byte-identical", "--offline"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("scan help lacks %q:\n%s", want, buf.String())
		}
	}
}

// With SOURCE_DATE_EPOCH set, two scans of one tree, a clock tick apart, write
// the same bytes in every artifact: findings, SARIF, both SBOMs, the AI
// inventory and the HTML report. Without it the reports carry the wall clock,
// which is the premise the control run checks.
func TestScanOutputsByteIdenticalWithSourceDateEpoch(t *testing.T) {
	src := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(src, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("package.json", `{"name":"x","dependencies":{"lodash":"4.17.15"}}`)
	write("package-lock.json", `{"lockfileVersion":3,"packages":{"":{"name":"x"},"node_modules/lodash":{"version":"4.17.15"}}}`)
	write("app.py", "import openai\nclient = openai.OpenAI()\nclient.chat.completions.create(model='gpt-4o', messages=[])\n")
	write("Dockerfile", "FROM node:latest\n")

	scan := func(out string) {
		if code := run([]string{"--quiet", "--format", "all", "--output", out, "scan", "--offline", src}); code > 1 {
			t.Fatalf("scan exited %d", code)
		}
	}
	read := func(dir string) map[string]string {
		m := map[string]string{}
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			b, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				t.Fatal(err)
			}
			m[e.Name()] = string(b)
		}
		return m
	}

	t.Setenv("SOURCE_DATE_EPOCH", "1700000000")
	a, b := filepath.Join(t.TempDir(), "a"), filepath.Join(t.TempDir(), "b")
	scan(a)
	time.Sleep(1100 * time.Millisecond)
	scan(b)
	ra, rb := read(a), read(b)
	for _, want := range []string{"findings.json", "results.sarif", "sbom.cdx.json", "sbom.spdx.json", "ai.inventory.json"} {
		if _, ok := ra[want]; !ok {
			t.Fatalf("scan did not write %s (wrote %v)", want, keys(ra))
		}
	}
	for name, content := range ra {
		if content != rb[name] {
			t.Errorf("%s differs between two scans with SOURCE_DATE_EPOCH set", name)
		}
	}

	// Control: without it the clock leaks into at least one artifact.
	t.Setenv("SOURCE_DATE_EPOCH", "")
	c, d := filepath.Join(t.TempDir(), "c"), filepath.Join(t.TempDir(), "d")
	scan(c)
	time.Sleep(1100 * time.Millisecond)
	scan(d)
	rc, rd := read(c), read(d)
	if rc["findings.json"] == rd["findings.json"] {
		t.Error("control: findings.json identical without SOURCE_DATE_EPOCH; the test cannot tell the env var matters")
	}
}

func keys(m map[string]string) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
