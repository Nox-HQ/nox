package fix

import (
	"regexp"
	"strings"

	"github.com/nox-hq/nox/core/findings"
)

// ContentFix is a deterministic, template-free line transform for a rule whose
// remediation is mechanical and unambiguous: a hardening boolean flip or an
// exact value swap. Re matches the insecure token on the finding's line; Repl is
// the replacement, using $1/$2 capture-group backrefs to preserve the
// surrounding indentation, keys, and quotes.
type ContentFix struct {
	Re      *regexp.Regexp
	Repl    string
	Summary string
	// Review is why a human should look at the change before it is applied, or
	// "" when the change cannot alter what the deployed system does. Every one
	// of these edits is mechanical, but "mechanical" is not "harmless": turning
	// a hardening flag on can stop a workload that relied on it being off, and
	// nox cannot see the workload.
	Review string
}

// ContentFixes maps a rule ID to its deterministic fix. Only rules whose
// remediation has ONE correct, judgment-free answer are listed -- a secure
// default flip or a safe value swap. Rules that need a choice (a non-root UID,
// a pinned image digest, an explicit tool allowlist, a rotated secret) are
// deliberately absent: nox never guesses a value.
var ContentFixes = map[string]ContentFix{
	// Kubernetes: disable a dangerous flag.
	"IAC-007": {regexp.MustCompile(`(?i)(privileged\s*:\s*)true`), "${1}false", "privileged: true → false",
		"the container may need privileged mode, and without it may fail to start"},
	"IAC-008": {regexp.MustCompile(`(?i)(hostNetwork\s*:\s*)true`), "${1}false", "hostNetwork: true → false",
		"the workload may rely on the node's network, and without it may lose connectivity"},
	"IAC-009": {regexp.MustCompile(`(?i)(allowPrivilegeEscalation\s*:\s*)true`), "${1}false", "allowPrivilegeEscalation: true → false",
		"a setuid binary in the image would stop working"},
	"IAC-026": {regexp.MustCompile(`(?i)(hostPID\s*:\s*)true`), "${1}false", "hostPID: true → false",
		"the workload may rely on seeing the node's processes"},
	"IAC-027": {regexp.MustCompile(`(?i)(hostIPC\s*:\s*)true`), "${1}false", "hostIPC: true → false",
		"the workload may rely on the node's shared memory"},
	"IAC-030": {regexp.MustCompile(`(?i)(automountServiceAccountToken\s*:\s*)true`), "${1}false", "automountServiceAccountToken: true → false",
		"the workload may call the Kubernetes API with that token"},
	// Kubernetes: enable a protective flag.
	"IAC-035": {regexp.MustCompile(`(?i)(runAsNonRoot\s*:\s*)false`), "${1}true", "runAsNonRoot: false → true",
		"if the image runs as root, the pod will be refused at start"},
	"IAC-029": {regexp.MustCompile(`(?i)(readOnlyRootFilesystem\s*:\s*)false`), "${1}true", "readOnlyRootFilesystem: false → true",
		"an application that writes to its own filesystem would start failing"},
	// CI: fail on error instead of swallowing it. Changes what CI reports,
	// never what is deployed.
	"IAC-018": {regexp.MustCompile(`(?i)(continue-on-error\s*:\s*)true`), "${1}false", "continue-on-error: true → false", ""},
	// Terraform: enable encryption / TLS-only transport.
	"IAC-037": {regexp.MustCompile(`(?i)(storage_encrypted\s*=\s*)false`), "${1}true", "storage_encrypted = false → true",
		"on an existing database this forces the instance to be replaced"},
	"IAC-042": {regexp.MustCompile(`(?i)(enable_https_traffic_only\s*=\s*)false`), "${1}true", "enable_https_traffic_only = false → true",
		"clients that connect over plain HTTP would be refused"},
	// Terraform: HTTPS listener, private ACL.
	"IAC-041": {regexp.MustCompile(`(?i)(protocol\s*=\s*["'])HTTP(["'])`), "${1}HTTPS${2}", `protocol "HTTP" → "HTTPS"`,
		"an HTTPS listener needs a certificate configured alongside it"},
	"IAC-040": {regexp.MustCompile(`(?i)(acl\s*=\s*["'])(?:public-read|public-read-write)(["'])`), "${1}private${2}", `acl "public-read" → "private"`,
		"anything that reads this bucket publicly would lose access"},
	// Dockerfile: COPY instead of ADD (ADD's implicit fetch/extract is a footgun).
	"IAC-003": {regexp.MustCompile(`(?im)(^\s*)ADD(\s+)`), "${1}COPY${2}", "ADD → COPY",
		"ADD also downloads URLs and unpacks archives; COPY does neither"},
}

// Patch is one line edit a ContentFix proposes for a finding.
type Patch struct {
	RuleID  string `json:"rule_id"`
	File    string `json:"file"`
	Line    int    `json:"line"`
	Summary string `json:"summary"`
	Before  string `json:"before"`
	After   string `json:"after"`
	// Review is why the edit needs a human's look, or "" when it does not.
	Review string `json:"review,omitempty"`
}

// PlanPatch computes the edit a finding's rule proposes for the file's lines.
// It reports false when the rule has no deterministic fix, the line is out of
// range, or the line no longer holds the insecure token (already fixed, or the
// file moved since the scan): nothing is proposed that would not change a byte.
func PlanPatch(f *findings.Finding, lines []string) (Patch, bool) {
	cf, ok := ContentFixes[f.RuleID]
	if !ok {
		return Patch{}, false
	}
	idx := f.Location.StartLine - 1
	if idx < 0 || idx >= len(lines) {
		return Patch{}, false
	}
	before := lines[idx]
	after := cf.Re.ReplaceAllString(before, cf.Repl)
	if after == before {
		return Patch{}, false
	}
	return Patch{
		RuleID: f.RuleID, File: f.Location.FilePath, Line: f.Location.StartLine,
		Summary: cf.Summary, Before: strings.TrimSpace(before), After: strings.TrimSpace(after),
		Review: cf.Review,
	}, true
}

// Apply rewrites p's line in lines, reporting whether it changed anything. It
// recomputes from the live line rather than trusting p.After, so a stale plan
// cannot write a line it never saw.
func (p Patch) Apply(lines []string) bool {
	idx := p.Line - 1
	cf, ok := ContentFixes[p.RuleID]
	if !ok || idx < 0 || idx >= len(lines) {
		return false
	}
	next := cf.Re.ReplaceAllString(lines[idx], cf.Repl)
	if next == lines[idx] {
		return false
	}
	lines[idx] = next
	return true
}

// ActionsPinRules are the rules `nox fix --actions` resolves: a GitHub Action
// referenced by a mutable tag instead of a commit.
var ActionsPinRules = map[string]bool{"IAC-013": true}
