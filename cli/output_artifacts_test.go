package main

import (
	"os"
	"regexp"
	"testing"

	nox "github.com/nox-hq/nox/core"
)

// outputWriteRe finds every report file this file writes into the scan's
// output directory.
var outputWriteRe = regexp.MustCompile(`filepath\.Join\(outputDir, "([^"]+)"\)`)

// TestEveryWrittenArtifactIsExcludedFromTheScan reads this file's own source and
// checks each report it writes against the exclusion list in core.
//
// core owns the list of artifacts a scan must not read back (see
// ScanOptions.OutputDir); this file owns the code that writes them. A list
// maintained in one place and used in another drifts, and the drift is silent:
// a new report format is added here, nothing excludes it, and the next scan of
// the same tree reports findings on it.
//
// So the check reads this file's own source. It is the cheapest way to make
// "every artifact we write" a fact rather than a memory.
func TestEveryWrittenArtifactIsExcludedFromTheScan(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("reading main.go: %v", err)
	}
	matches := outputWriteRe.FindAllStringSubmatch(string(src), -1)
	if len(matches) == 0 {
		t.Fatal("found no artifact writes in main.go; the pattern no longer matches " +
			"the code it guards, so this test proves nothing")
	}

	excluded := map[string]bool{}
	for _, n := range nox.OutputArtifactNames() {
		excluded[n] = true
	}
	seen := map[string]bool{}
	for _, m := range matches {
		name := m[1]
		if seen[name] {
			continue
		}
		seen[name] = true
		if !excluded[name] {
			t.Errorf("nox scan writes %q into the output directory, and core does not "+
				"exclude it from discovery. Scanning a tree twice with --output . will "+
				"report findings on it. Add it to outputArtifactNames in core/scan.go", name)
		}
	}
	t.Logf("checked %d written artifact(s) against %d excluded", len(seen), len(excluded))
}
