// Package provenance flags dependencies whose origin cannot be verified against
// a signed package registry — the deterministic, offline half of supply-chain
// provenance (OWASP ASI04 / SLSA). It reports two shapes that a version-based
// SCA misses because there is no CVE, only an unverifiable source:
//
//   - PROV-001: a dependency pulled from a VCS, raw URL, or tarball instead of
//     a signed registry, so no integrity hash or publisher attestation backs it.
//   - PROV-002: a VCS dependency pinned to a mutable ref (branch/tag) rather than
//     an immutable commit SHA, so the code can change under you.
//
// Live signature verification (sigstore/cosine, SLSA attestation fetch) needs
// the network and is intentionally left to an opt-in plugin; this analyzer never
// makes a network call.
package provenance

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/rules"
)

// Analyzer detects unverifiable dependency provenance.
type Analyzer struct{}

// NewAnalyzer returns a provenance analyzer.
func NewAnalyzer() *Analyzer { return &Analyzer{} }

// Rules returns the rule set for the provenance analyzer.
func (a *Analyzer) Rules() *rules.RuleSet {
	rs := rules.NewRuleSet()
	rs.Add(&rules.Rule{
		ID:          "PROV-001",
		Version:     "1.0",
		Description: "Dependency from a non-registry source (VCS/URL/tarball) — provenance cannot be verified",
		Severity:    findings.SeverityMedium,
		Confidence:  findings.ConfidenceMedium,
		Tags:        []string{"dependency", "supply-chain", "provenance", "slsa", "owasp-asi04"},
		Remediation: "This dependency is pulled from a VCS repository, raw URL, or tarball rather than a signed package registry, so no integrity hash or publisher attestation backs it. Prefer the registry-published package. If a non-registry source is unavoidable, pin it to an immutable commit SHA and vendor or hash-lock the artifact (npm: commit-ish; pip: --hash or #sha256=).",
		References:  []string{"https://slsa.dev/", "https://genai.owasp.org/llmrisk/llm03-supply-chain/"},
		Metadata:    map[string]string{"cwe": "CWE-1357"},
	})
	rs.Add(&rules.Rule{
		ID:          "PROV-002",
		Version:     "1.0",
		Description: "VCS dependency pinned to a mutable ref instead of an immutable commit SHA",
		Severity:    findings.SeverityHigh,
		Confidence:  findings.ConfidenceMedium,
		Tags:        []string{"dependency", "supply-chain", "provenance", "slsa", "owasp-asi04"},
		Remediation: "This VCS dependency is pinned to a branch or tag, both of which are mutable — the referenced code can be force-pushed or re-tagged after review. Pin to the full 40-character commit SHA so the exact tree is immutable and reproducible.",
		References:  []string{"https://slsa.dev/spec/v1.0/requirements", "https://genai.owasp.org/llmrisk/llm03-supply-chain/"},
		Metadata:    map[string]string{"cwe": "CWE-829"},
	})
	return rs
}

// ScanArtifacts inspects dependency manifests for unverifiable provenance.
func (a *Analyzer) ScanArtifacts(ctx context.Context, artifacts []discovery.Artifact) (*findings.FindingSet, error) {
	fs := findings.NewFindingSet()
	for i := range artifacts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		art := artifacts[i]
		base := strings.ToLower(filepath.Base(art.Path))
		content, err := os.ReadFile(art.AbsPath)
		if err != nil {
			continue
		}
		switch {
		case base == "package.json":
			scanPackageJSON(fs, art.Path, content)
		case base == "requirements.txt" || (strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt")):
			scanRequirements(fs, art.Path, content)
		}
	}
	return fs, nil
}

var shaRe = regexp.MustCompile(`^[0-9a-fA-F]{7,40}$`)

func addFinding(fs *findings.FindingSet, ruleID, path string, line int, sev findings.Severity, msg string) {
	fs.Add(findings.Finding{
		RuleID:     ruleID,
		Severity:   sev,
		Confidence: findings.ConfidenceMedium,
		Location:   findings.Location{FilePath: path, StartLine: line, EndLine: line},
		Message:    msg,
	})
}

// classifyNPMSpec classifies a package.json dependency version spec. It returns
// the rule ID to raise ("" when the source is a normal registry spec) plus a
// human-readable reason.
func classifyNPMSpec(spec string) (ruleID, reason string) {
	s := strings.TrimSpace(spec)
	low := strings.ToLower(s)
	switch {
	case s == "", strings.HasPrefix(low, "file:"), strings.HasPrefix(low, "link:"),
		strings.HasPrefix(low, "workspace:"), strings.HasPrefix(low, "portal:"),
		strings.HasPrefix(low, "npm:"), strings.HasPrefix(s, "."), strings.HasPrefix(s, "/"):
		return "", "" // local / registry alias — not a provenance concern here
	}
	isVCS := strings.HasPrefix(low, "git+") || strings.HasPrefix(low, "git://") ||
		strings.HasPrefix(low, "github:") || strings.HasPrefix(low, "gitlab:") ||
		strings.HasPrefix(low, "bitbucket:") || strings.HasPrefix(low, "gist:")
	// Shorthand "owner/repo" or "owner/repo#ref": a slash, no protocol, not a range.
	if !isVCS && looksLikeGitHubShorthand(s) {
		isVCS = true
	}
	if isVCS {
		if ref, ok := vcsRef(s); ok && shaRe.MatchString(ref) {
			return "PROV-001", "VCS dependency (pinned to a commit, but not from a signed registry)"
		}
		return "PROV-002", "VCS dependency pinned to a mutable ref (branch/tag) or no ref"
	}
	// Raw URL tarball.
	if (strings.HasPrefix(low, "http://") || strings.HasPrefix(low, "https://")) &&
		(strings.Contains(low, ".tgz") || strings.Contains(low, ".tar")) {
		return "PROV-001", "dependency fetched from a raw tarball URL (no registry integrity)"
	}
	return "", "" // semver range, tag, "*", "latest" — registry source
}

func looksLikeGitHubShorthand(s string) bool {
	if strings.Contains(s, "://") || strings.ContainsAny(s, "^~<>= ") {
		return false
	}
	base := s
	if i := strings.IndexAny(base, "#"); i >= 0 {
		base = base[:i]
	}
	if base == "" || strings.HasPrefix(base, "@") { // @scope/name is a registry name, not a value
		return false
	}
	parts := strings.Split(base, "/")
	return len(parts) == 2 && parts[0] != "" && parts[1] != ""
}

func vcsRef(s string) (string, bool) {
	if i := strings.LastIndex(s, "#"); i >= 0 {
		return s[i+1:], true
	}
	return "", false
}

func scanPackageJSON(fs *findings.FindingSet, path string, content []byte) {
	var pkg struct {
		Dependencies         map[string]string `json:"dependencies"`
		DevDependencies      map[string]string `json:"devDependencies"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
	}
	if err := json.Unmarshal(content, &pkg); err != nil {
		return
	}
	text := string(content)
	for _, deps := range []map[string]string{pkg.Dependencies, pkg.DevDependencies, pkg.OptionalDependencies} {
		for name, spec := range deps {
			ruleID, reason := classifyNPMSpec(spec)
			if ruleID == "" {
				continue
			}
			sev := findings.SeverityMedium
			if ruleID == "PROV-002" {
				sev = findings.SeverityHigh
			}
			addFinding(fs, ruleID, path, lineOfKey(text, name), sev,
				"Dependency \""+name+"\" ("+spec+"): "+reason+".")
		}
	}
}

// lineOfKey returns the 1-based line where a JSON key first appears, so the
// finding points at the offending dependency. Falls back to line 1.
func lineOfKey(text, key string) int {
	needle := "\"" + key + "\""
	if i := strings.Index(text, needle); i >= 0 {
		return 1 + strings.Count(text[:i], "\n")
	}
	return 1
}

func scanRequirements(fs *findings.FindingSet, path string, content []byte) {
	for i, raw := range strings.Split(string(content), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Editable installs: strip the -e/--editable flag and evaluate the rest.
		line = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(line, "--editable"), "-e"))
		low := strings.ToLower(line)
		isVCS := strings.HasPrefix(low, "git+") || strings.HasPrefix(low, "hg+") ||
			strings.HasPrefix(low, "svn+") || strings.HasPrefix(low, "bzr+")
		isURL := (strings.HasPrefix(low, "http://") || strings.HasPrefix(low, "https://")) &&
			(strings.Contains(low, ".whl") || strings.Contains(low, ".tar") || strings.Contains(low, ".zip"))
		switch {
		case isVCS:
			ref, ok := pyVCSRef(line)
			if ok && shaRe.MatchString(ref) {
				addFinding(fs, "PROV-001", path, i+1, findings.SeverityMedium,
					"Dependency from VCS ("+truncate(line)+"): pinned to a commit but not from a signed registry.")
			} else {
				addFinding(fs, "PROV-002", path, i+1, findings.SeverityHigh,
					"Dependency from VCS ("+truncate(line)+"): pinned to a mutable ref or no ref — pin to a commit SHA.")
			}
		case isURL:
			if strings.Contains(low, "#sha256=") || strings.Contains(low, "#md5=") {
				continue // hash-verified direct URL
			}
			addFinding(fs, "PROV-001", path, i+1, findings.SeverityMedium,
				"Dependency from a direct URL ("+truncate(line)+"): no registry integrity or hash.")
		}
	}
}

// pyVCSRef extracts the ref from a pip VCS requirement of the form
// git+https://host/repo@<ref>#egg=name. Returns ok=false when no @ref present.
func pyVCSRef(line string) (string, bool) {
	// Consider only the part before any #egg / fragment.
	main := line
	if i := strings.IndexByte(main, '#'); i >= 0 {
		main = main[:i]
	}
	if i := strings.LastIndex(main, "@"); i >= 0 {
		return main[i+1:], true
	}
	return "", false
}

func truncate(s string) string {
	if len(s) > 60 {
		return s[:57] + "..."
	}
	return s
}
