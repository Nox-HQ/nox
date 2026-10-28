package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/fix"
)

// runContentFix reads findings.json and, for each finding whose rule has a
// deterministic fix, computes the patched line. By default it previews the
// diff and applies nothing (nox never auto-rewrites code); --write applies.
func runContentFix(inputPath string, write bool) int {
	raw, err := os.ReadFile(inputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: reading %s: %v\n", inputPath, err)
		return 2
	}
	var doc struct {
		Findings []findings.Finding `json:"findings"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		fmt.Fprintf(os.Stderr, "error: parsing %s: %v\n", inputPath, err)
		return 2
	}

	// Collect fixable findings per file, preserving rule + line.
	type edit struct {
		line   int
		ruleID string
	}
	byFile := map[string][]edit{}
	for i := range doc.Findings {
		f := doc.Findings[i]
		if _, ok := fix.ContentFixes[f.RuleID]; !ok {
			continue
		}
		byFile[f.Location.FilePath] = append(byFile[f.Location.FilePath], edit{line: f.Location.StartLine, ruleID: f.RuleID})
	}
	if len(byFile) == 0 {
		fmt.Println("fix: no findings with a deterministic fix (content fixes cover the mechanical IAC misconfigurations)")
		return 0
	}

	files := make([]string, 0, len(byFile))
	for f := range byFile {
		files = append(files, f)
	}
	sort.Strings(files)

	available, applied := 0, 0
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  skip %s: %v\n", file, err)
			continue
		}
		lines := strings.Split(string(data), "\n")
		edits := byFile[file]
		sort.Slice(edits, func(i, j int) bool { return edits[i].line < edits[j].line })

		changed := false
		for _, e := range edits {
			idx := e.line - 1
			if idx < 0 || idx >= len(lines) {
				continue
			}
			f := findings.Finding{RuleID: e.ruleID, Location: findings.Location{StartLine: e.line}}
			patch, ok := fix.PlanPatch(&f, lines)
			if !ok {
				continue // already fixed, or the line moved since the scan
			}
			available++
			fmt.Printf("%s:%d  %s (%s)\n", file, e.line, patch.Summary, e.ruleID)
			fmt.Printf("  - %s\n", patch.Before)
			fmt.Printf("  + %s\n", patch.After)
			if write {
				patch.Apply(lines)
				changed = true
				applied++
			}
		}
		if write && changed {
			if err := os.WriteFile(file, []byte(strings.Join(lines, "\n")), 0o644); err != nil {
				fmt.Fprintf(os.Stderr, "  error writing %s: %v\n", file, err)
				return 2
			}
		}
	}

	if write {
		fmt.Printf("fix: applied %d change(s)\n", applied)
	} else if available > 0 {
		fmt.Printf("fix: %d deterministic change(s) available — re-run with --content --write to apply\n", available)
	}
	return 0
}
