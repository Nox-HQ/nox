package main

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/nox-hq/nox/core/findings"
)

// contentFix is a deterministic, template-free line transform for a rule whose
// remediation is mechanical and unambiguous — a hardening boolean flip or an
// exact value swap. re matches the insecure token on the finding's line; repl
// is the replacement, using $1/$2 capture-group backrefs to preserve the
// surrounding indentation, keys, and quotes.
type contentFix struct {
	re      *regexp.Regexp
	repl    string
	summary string
}

// contentFixes maps a rule ID to its deterministic fix. Only rules whose
// remediation has ONE correct, judgment-free answer are listed — a secure
// default flip or a safe value swap. Rules that need a choice (a non-root UID,
// a pinned image digest, an explicit tool allowlist, a rotated secret) are
// deliberately absent: nox never guesses a value.
var contentFixes = map[string]contentFix{
	// Kubernetes: disable a dangerous flag.
	"IAC-007": {regexp.MustCompile(`(?i)(privileged\s*:\s*)true`), "${1}false", "privileged: true → false"},
	"IAC-008": {regexp.MustCompile(`(?i)(hostNetwork\s*:\s*)true`), "${1}false", "hostNetwork: true → false"},
	"IAC-009": {regexp.MustCompile(`(?i)(allowPrivilegeEscalation\s*:\s*)true`), "${1}false", "allowPrivilegeEscalation: true → false"},
	"IAC-026": {regexp.MustCompile(`(?i)(hostPID\s*:\s*)true`), "${1}false", "hostPID: true → false"},
	"IAC-027": {regexp.MustCompile(`(?i)(hostIPC\s*:\s*)true`), "${1}false", "hostIPC: true → false"},
	"IAC-030": {regexp.MustCompile(`(?i)(automountServiceAccountToken\s*:\s*)true`), "${1}false", "automountServiceAccountToken: true → false"},
	// Kubernetes: enable a protective flag.
	"IAC-035": {regexp.MustCompile(`(?i)(runAsNonRoot\s*:\s*)false`), "${1}true", "runAsNonRoot: false → true"},
	"IAC-029": {regexp.MustCompile(`(?i)(readOnlyRootFilesystem\s*:\s*)false`), "${1}true", "readOnlyRootFilesystem: false → true"},
	// CI: fail on error instead of swallowing it.
	"IAC-018": {regexp.MustCompile(`(?i)(continue-on-error\s*:\s*)true`), "${1}false", "continue-on-error: true → false"},
	// Terraform: enable encryption / TLS-only transport.
	"IAC-037": {regexp.MustCompile(`(?i)(storage_encrypted\s*=\s*)false`), "${1}true", "storage_encrypted = false → true"},
	"IAC-042": {regexp.MustCompile(`(?i)(enable_https_traffic_only\s*=\s*)false`), "${1}true", "enable_https_traffic_only = false → true"},
	// Terraform: HTTPS listener, private ACL.
	"IAC-041": {regexp.MustCompile(`(?i)(protocol\s*=\s*["'])HTTP(["'])`), "${1}HTTPS${2}", `protocol "HTTP" → "HTTPS"`},
	"IAC-040": {regexp.MustCompile(`(?i)(acl\s*=\s*["'])(?:public-read|public-read-write)(["'])`), "${1}private${2}", `acl "public-read" → "private"`},
	// Dockerfile: COPY instead of ADD (ADD's implicit fetch/extract is a footgun).
	"IAC-003": {regexp.MustCompile(`(?im)(^\s*)ADD(\s+)`), "${1}COPY${2}", "ADD → COPY"},
}

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
		if _, ok := contentFixes[f.RuleID]; !ok {
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
			fx := contentFixes[e.ruleID]
			old := lines[idx]
			newLine := fx.re.ReplaceAllString(old, fx.repl)
			if newLine == old {
				continue // already fixed, or the line moved since the scan
			}
			available++
			fmt.Printf("%s:%d  %s (%s)\n", file, e.line, fx.summary, e.ruleID)
			fmt.Printf("  - %s\n", strings.TrimSpace(old))
			fmt.Printf("  + %s\n", strings.TrimSpace(newLine))
			if write {
				lines[idx] = newLine
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
