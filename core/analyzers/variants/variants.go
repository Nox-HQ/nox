// Package variants detects code that matches the root-cause pattern of a known
// CVE — "variants" of a published vulnerability that may not correspond to a
// pinned dependency version but reproduce the same insecure shape in
// first-party code. Detection is deterministic and offline: an embedded set of
// CVE signatures (regular expressions distilled from each advisory's root
// cause) is matched line-by-line against source and configuration files.
package variants

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/rules"
)

//go:embed data/signatures.json
var signaturesJSON []byte

// signature is one CVE-variant detector loaded from embedded data.
type signature struct {
	ID          string   `json:"id"`
	CVE         string   `json:"cve"`
	Title       string   `json:"title"`
	Severity    string   `json:"severity"`
	Confidence  string   `json:"confidence"`
	Exts        []string `json:"exts"`
	Pattern     string   `json:"pattern"`
	Exclude     string   `json:"exclude"`
	Remediation string   `json:"remediation"`
	References  []string `json:"references"`
	// VulnClass is the underlying vulnerability class (e.g. "ssti", "xss").
	// Optional; when set it lets the pipeline dedup a signature against another
	// analyzer's finding of the same class at the same location.
	VulnClass string `json:"vuln_class,omitempty"`

	re      *regexp.Regexp
	exclude *regexp.Regexp
}

// Analyzer matches embedded CVE-variant signatures against source/config files.
type Analyzer struct {
	sigs []signature

	// loadErr is set when the embedded signature database could not be parsed
	// at all, leaving the analyzer with no signatures. Exposed via LoadErr so
	// the pipeline can report that CVE-variant detection did not run, rather
	// than emitting zero findings and calling it clean.
	loadErr error
}

// LoadErr reports a whole-database load failure, or nil when the signature
// database parsed. A non-nil value means no VARIANT-* rule can match.
func (a *Analyzer) LoadErr() error { return a.loadErr }

// NewAnalyzer returns a variants analyzer with the embedded signatures compiled.
// Signatures that fail to compile are skipped so one bad entry can't disable
// the analyzer.
//
// LoadErr reports whole-database failure, which is a different matter from a
// bad entry: an unparseable signatures file leaves the analyzer with nothing
// to match, so every VARIANT-* detection is off while the scan reports success.
// Because the data is compiled in, that failure would ship to every user at
// once and look like a quiet week for CVE variants.
func NewAnalyzer() *Analyzer {
	var sigs []signature
	var loadErr error
	if err := json.Unmarshal(signaturesJSON, &sigs); err != nil {
		loadErr = fmt.Errorf("variant signature database could not be parsed: %w", err)
	}
	compiled := sigs[:0]
	for i := range sigs {
		re, err := regexp.Compile(sigs[i].Pattern)
		if err != nil {
			continue
		}
		sigs[i].re = re
		if sigs[i].Exclude != "" {
			if ex, err := regexp.Compile(sigs[i].Exclude); err == nil {
				sigs[i].exclude = ex
			}
		}
		compiled = append(compiled, sigs[i])
	}
	return &Analyzer{sigs: compiled, loadErr: loadErr}
}

// Signatures returns the compiled CVE-variant signatures (for the `variants`
// command to enumerate and filter by CVE).
func (a *Analyzer) Signatures() []signature { return a.sigs }

// Rules returns the rule set for the CVE-variant analyzer, one rule per
// signature so findings carry the CVE, remediation, and references.
func (a *Analyzer) Rules() *rules.RuleSet {
	rs := rules.NewRuleSet()
	for i := range a.sigs {
		s := a.sigs[i]
		rs.Add(&rules.Rule{
			ID:          s.ID,
			Version:     "1.0",
			Description: s.Title,
			Severity:    findings.Severity(s.Severity),
			Confidence:  findings.Confidence(s.Confidence),
			Tags:        []string{"cve-variant", "sast", strings.ToLower(s.CVE)},
			Remediation: s.Remediation,
			References:  s.References,
			Metadata:    map[string]string{"cve": s.CVE},
		})
	}
	return rs
}

// ScanArtifacts matches every signature against each source/config artifact.
func (a *Analyzer) ScanArtifacts(ctx context.Context, artifacts []discovery.Artifact) (*findings.FindingSet, error) {
	fs := findings.NewFindingSet()
	for i := range artifacts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		art := artifacts[i]
		if art.Type != discovery.Source && art.Type != discovery.Config {
			continue
		}
		content, err := os.ReadFile(art.AbsPath)
		if err != nil {
			continue
		}
		a.scanFile(fs, art.Path, content)
	}
	return fs, nil
}

func (a *Analyzer) scanFile(fs *findings.FindingSet, path string, content []byte) {
	ext := strings.ToLower(filepath.Ext(path))
	lines := strings.Split(string(content), "\n")
	for i := range a.sigs {
		s := &a.sigs[i]
		if !s.matchesExt(ext) {
			continue
		}
		for ln, line := range lines {
			if !s.re.MatchString(line) {
				continue
			}
			if s.exclude != nil && s.exclude.MatchString(line) {
				continue
			}
			meta := map[string]string{"cve": s.CVE}
			if s.VulnClass != "" {
				meta["vuln_class"] = s.VulnClass
			}
			fs.Add(findings.Finding{
				RuleID:     s.ID,
				Severity:   findings.Severity(s.Severity),
				Confidence: findings.Confidence(s.Confidence),
				Location:   findings.Location{FilePath: path, StartLine: ln + 1, EndLine: ln + 1},
				Message:    s.CVE + " variant: " + s.Title,
				Metadata:   meta,
			})
		}
	}
}

// matchesExt reports whether the signature applies to a file with the given
// extension. An empty Exts list means the signature applies to every file.
func (s *signature) matchesExt(ext string) bool {
	if len(s.Exts) == 0 {
		return true
	}
	for _, e := range s.Exts {
		if strings.EqualFold(e, ext) {
			return true
		}
	}
	return false
}
