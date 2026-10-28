package change

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/nox-hq/nox-core/degrade"
	nox "github.com/nox-hq/nox/core"
	"github.com/nox-hq/nox/core/analyzers/ai"
	"github.com/nox-hq/nox/core/report"
)

// InventoryFile is the name of the AI inventory a scan writes beside
// findings.json; LoadPrevious looks for it there.
const InventoryFile = "ai.inventory.json"

// FromScan builds a State from a scan held in memory. It is what `nox diff`
// compares and what a scan's own change summary is built from, so both read the
// same fields a findings.json round-trip would.
func FromScan(r *nox.ScanResult, label string) State {
	s := State{Label: label}
	if r == nil {
		return s
	}
	if r.Findings != nil {
		s.Findings = r.Findings.Findings()
	}
	s.Leads = r.ReportLeads()
	// The scan knows its leads whenever the authorization analyzer was in
	// scope; an empty list then means "looked, none".
	s.LeadsRecorded = r.Scope.RunsAnalyzer("authz")
	s.Inventory = r.AIInventory
	// The scan knows its infrastructure whenever the IaC checks were in scope;
	// nil then means "looked, none".
	s.Infrastructure = r.Infrastructure
	s.InfrastructureRecorded = r.Scope.RunsAnalyzer("iac")
	for _, d := range r.Degradations {
		if d.Blocks() {
			s.Incomplete = append(s.Incomplete, d.Detail)
		}
		if d.Kind == degrade.OSV {
			s.AdvisoryLookup = LookupFailed
		}
		if d.Kind == degrade.IntelIncomplete && s.AdvisoryLookup == "" {
			s.AdvisoryLookup = LookupIncomplete
		}
	}
	if r.AdvisoryLookupSkipped {
		s.AdvisoryLookup = LookupDisabled
	}
	if !r.Scope.Full() {
		for _, sc := range r.Scope.Ran() {
			s.Scanned = append(s.Scanned, string(sc))
		}
		if s.Scanned == nil {
			s.Scanned = []string{}
		}
	}
	return s
}

// LoadPrevious reads a prior scan from a findings.json and, when one sits
// beside it, its ai.inventory.json. A missing inventory is not an error: the
// state then has none, and the comparison says AI changes were not compared.
// A findings.json that cannot be read is an error, never an empty state: "no
// earlier scan" and "an earlier scan that found nothing" must stay different.
func LoadPrevious(findingsPath, label string) (State, error) {
	rep, err := report.LoadFindingsFileReport(findingsPath)
	if err != nil {
		return State{}, err
	}
	var inv *ai.Inventory
	invPath := filepath.Join(filepath.Dir(findingsPath), InventoryFile)
	if raw, rerr := os.ReadFile(invPath); rerr == nil { //nolint:gosec // sibling of the caller-supplied scan artifact
		var parsed ai.Inventory
		if jerr := json.Unmarshal(raw, &parsed); jerr != nil {
			return State{}, fmt.Errorf("%s: %w", invPath, jerr)
		}
		inv = &parsed
	}
	return FromReport(rep, inv, label), nil
}
