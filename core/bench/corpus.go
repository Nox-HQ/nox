package bench

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// expectMarker is the inline annotation keyword. A line containing
// `nox-expect: <RuleID>[, <RuleID>...]` declares that the listed rules are
// expected to fire on that line. The keyword is matched case-insensitively so
// authors can shout it if they like. We deliberately require the annotation to
// live on the same line as the code that should fire — this keeps each sample
// self-contained and makes the ground truth impossible to misread: the
// expectation sits exactly where the finding should land.
var expectMarker = regexp.MustCompile(`(?i)nox-expect\s*:\s*(.*)$`)

// docExtensions are treated as documentation, not samples. The corpus README
// explains the annotation format and would otherwise be parsed as if its
// examples were real expectations. Documentation is never scanned as a sample,
// so any `nox-expect` text inside it must be ignored.
var docExtensions = map[string]bool{
	".md":       true,
	".mdx":      true,
	".markdown": true,
	".rst":      true,
	".txt":      true,
}

// IsDocFile reports whether a path is a documentation file (by extension) that
// the corpus treats as prose, not a sample. ParseCorpus already skips these when
// gathering expectations; the scanner side uses this to drop findings on doc
// files so a README explaining the annotation format cannot score as a false
// positive. Exported so the CLI's scan path can apply the same rule the corpus
// parser does, keeping both sides consistent.
func IsDocFile(path string) bool {
	return docExtensions[strings.ToLower(filepath.Ext(path))]
}

// harnessArtifacts are files that live in a corpus directory but are the
// harness's own output, not labeled samples — a finding on them must never
// score. baseline.json is the committed ratchet snapshot; because it sits inside
// the scanned corpus dir, scanning it would otherwise self-inflict a false
// positive (its JSON body contains rule IDs and sample paths).
var harnessArtifacts = map[string]bool{"baseline.json": true}

// IsNonSample reports whether a corpus-directory path is a documentation file or
// a harness artifact rather than a labeled sample. Both the corpus parser (when
// gathering expectations) and the scan side (when scoring findings) use it so
// the two stay consistent and neither docs nor the baseline snapshot can score.
func IsNonSample(path string) bool {
	return IsDocFile(path) || harnessArtifacts[filepath.Base(path)]
}

// ParseCorpus walks a labeled-corpus directory and returns every declared
// expectation. Each source file is read line by line; any line carrying a
// `nox-expect: <RuleID>` annotation yields one Expectation per listed rule,
// anchored to that line number (1-based). Files with no annotations contribute
// nothing — they are "clean" samples whose only role is to catch false
// positives at scan time.
//
// FilePath in every returned Expectation is relative to dir, matching the
// relative paths that findings.Location carries after a scan of the same
// directory, so the scorer can compare them directly.
func ParseCorpus(dir string) ([]Expectation, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("bench: corpus dir: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("bench: corpus path %q is not a directory", dir)
	}

	var expectations []Expectation
	walkErr := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if docExtensions[strings.ToLower(filepath.Ext(path))] {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		fileExpectations, err := parseFileExpectations(path, filepath.ToSlash(rel))
		if err != nil {
			return err
		}
		expectations = append(expectations, fileExpectations...)
		return nil
	})
	if walkErr != nil {
		return nil, fmt.Errorf("bench: walking corpus: %w", walkErr)
	}
	return expectations, nil
}

// parseFileExpectations reads one source file and extracts its annotations.
// relPath is the corpus-relative path stored on each Expectation.
func parseFileExpectations(absPath, relPath string) ([]Expectation, error) {
	f, err := os.Open(absPath) //nolint:gosec // corpus paths are operator-supplied, not user input
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // read-only file; close error is not actionable

	var out []Expectation
	scanner := bufio.NewScanner(f)
	// Allow long lines (minified JS, base64 blobs) without tripping the default
	// 64KiB token limit — corpus samples intentionally include such lines.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		for _, ruleID := range parseExpectationRuleIDs(scanner.Text()) {
			out = append(out, Expectation{RuleID: ruleID, FilePath: relPath, Line: lineNo})
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// parseExpectationRuleIDs returns the rule IDs declared by a `nox-expect`
// annotation on the line, or nil if the line has none. Rule IDs may be
// separated by commas and/or whitespace. Tokens are returned verbatim (after
// trimming) so a typo'd rule ID surfaces as a never-matched expectation rather
// than being silently dropped.
func parseExpectationRuleIDs(line string) []string {
	m := expectMarker.FindStringSubmatch(line)
	if m == nil {
		return nil
	}
	// Split the remainder on commas and whitespace. filepath-style tokens are
	// preserved; empty tokens (from doubled separators) are dropped.
	fields := strings.FieldsFunc(m[1], func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t'
	})
	var ids []string
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if f != "" {
			ids = append(ids, f)
		}
	}
	return ids
}
