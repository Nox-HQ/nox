package sbom

import (
	"fmt"
	"strings"

	"github.com/nox-hq/nox/core/analyzers/deps"
	"github.com/nox-hq/nox/core/findings"
)

// CDXAnalysis is a CycloneDX vulnerability analysis: the VEX part of the
// document, saying whether the vulnerability affects this product.
type CDXAnalysis struct {
	State         string `json:"state"`
	Justification string `json:"justification,omitempty"`
	Detail        string `json:"detail,omitempty"`
}

// justificationFor is the CycloneDX justification each refuted applicability
// step supports. A step that is not here gets `not_affected` with a detail and
// no justification rather than one it does not support.
var justificationFor = map[string]string{
	// The package the advisory names is not linked by this build.
	"symbol_used": "code_not_present",
	// It is linked, but nothing calls the affected code.
	"call_reachable": "code_not_reachable",
}

type verdictKey struct{ ecosystem, pkg, version, id string }

// WithFindings supplies the scan's findings, from which the SBOM records each
// dependency vulnerability nox decided is not impacting as a CycloneDX
// analysis (`not_affected`). Undecided and impacting verdicts carry none: an
// impacting verdict establishes that vulnerable code is used, not that it is
// exploitable, and CycloneDX has no state for that.
func (r *CycloneDXReporter) WithFindings(fs []findings.Finding) *CycloneDXReporter {
	r.verdicts = map[verdictKey]*CDXAnalysis{}
	for _, f := range fs {
		m := f.Metadata
		if f.RuleID != "VULN-001" || m["applicability"] != "not_impacting" {
			continue
		}
		stopped := m["applicability_stopped_at"]
		a := &CDXAnalysis{
			State:         "not_affected",
			Justification: justificationFor[stopped],
			Detail:        fmt.Sprintf("nox: decided not impacting; the %s step was refuted", stopped),
		}
		if scope := m["reach_scope"]; scope != "" {
			a.Detail += " (" + scope + ")"
		}
		ids := append([]string{m["vuln_id"]}, splitList(m["aliases"])...)
		for _, id := range ids {
			if id != "" {
				r.verdicts[verdictKey{m["ecosystem"], m["package"], m["version"], id}] = a
			}
		}
	}
	return r
}

// analysisFor returns the recorded verdict for one SBOM vulnerability entry,
// matching its id or any alias.
func (r *CycloneDXReporter) analysisFor(p deps.Package, v deps.Vulnerability) *CDXAnalysis {
	if len(r.verdicts) == 0 {
		return nil
	}
	for _, id := range append([]string{v.ID}, v.Aliases...) {
		if a, ok := r.verdicts[verdictKey{p.Ecosystem, p.Name, p.Version, id}]; ok {
			return a
		}
	}
	return nil
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
