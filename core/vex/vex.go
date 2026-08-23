// Package vex implements OpenVEX document parsing and application to findings.
//
// VEX (Vulnerability Exploitability eXchange) allows projects to communicate
// the status of vulnerabilities in their products. When a VEX document marks
// a CVE as "not_affected", the corresponding finding's status is updated so
// it no longer counts toward policy failures.
package vex

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/nox-hq/nox/core/findings"
)

// Status represents the VEX status of a vulnerability.
type Status string

// VEX status values per the OpenVEX specification.
const (
	StatusNotAffected        Status = "not_affected"
	StatusAffected           Status = "affected"
	StatusFixed              Status = "fixed"
	StatusUnderInvestigation Status = "under_investigation"
)

// statusOrder is the canonical order for rendering a status breakdown, so the
// summary line is deterministic.
var statusOrder = []Status{StatusAffected, StatusNotAffected, StatusUnderInvestigation, StatusFixed}

// Statement is a single VEX statement declaring the status of a vulnerability
// for a specific product.
type Statement struct {
	VulnerabilityID string   `json:"vulnerability"`
	Status          Status   `json:"status"`
	Justification   string   `json:"justification,omitempty"`
	ImpactStatement string   `json:"impact_statement,omitempty"`
	ActionStatement string   `json:"action_statement,omitempty"`
	Products        []string `json:"products,omitempty"`
	// NoxLocations is a non-OpenVEX auxiliary field listing finding locations
	// for the operator's convenience during triage. Consumers that don't
	// know about it can ignore it; OpenVEX validators will treat it as an
	// unknown extension key.
	NoxLocations   []string `json:"_nox_locations,omitempty"`
	NoxFingerprint string   `json:"_nox_fingerprint,omitempty"`
}

// UnmarshalJSON accepts both OpenVEX shapes for `vulnerability` and `products`.
//
// The spec changed them from plain strings to objects in v0.2.0:
//
//	v0.0.1 / v0.1.0    "vulnerability": "CVE-2024-1234"
//	v0.2.0             "vulnerability": {"@id": "CVE-2024-1234", "name": "..."}
//
//	v0.0.1 / v0.1.0    "products": ["pkg:golang/example"]
//	v0.2.0             "products": [{"@id": "pkg:golang/example"}]
//
// Reading only the older shape made nox reject documents that declare the
// current spec version, and it failed at LOAD time — before any scanning — so
// a repo that adopted v0.2.0 got no scan at all rather than a scan with
// unapplied waivers. Accepting both is the whole fix; nox keeps WRITING the
// string form, which every reader still understands.
func (s *Statement) UnmarshalJSON(data []byte) error {
	// The alias sheds the method set, so the embedded decode does not recurse.
	type alias Statement
	aux := struct {
		Vulnerability json.RawMessage `json:"vulnerability"`
		Products      json.RawMessage `json:"products"`
		*alias
	}{alias: (*alias)(s)}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	id, err := scalarOrObjectID(aux.Vulnerability)
	if err != nil {
		return fmt.Errorf("vulnerability: %w", err)
	}
	s.VulnerabilityID = id
	products, err := scalarOrObjectIDs(aux.Products)
	if err != nil {
		return fmt.Errorf("products: %w", err)
	}
	s.Products = products
	return nil
}

// scalarOrObjectID reads an identifier written either as a bare string or as an
// object carrying "@id" / "name". "@id" wins because it is the spec's identity
// field; "name" is the human-facing label and is only a fallback.
func scalarOrObjectID(raw json.RawMessage) (string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return "", nil
	}
	var str string
	if err := json.Unmarshal(raw, &str); err == nil {
		return str, nil
	}
	var obj struct {
		ID   string `json:"@id"`
		Name string `json:"name"`
	}
	if err := json.Unmarshal(raw, &obj); err != nil {
		return "", fmt.Errorf("expected a string or an object with @id/name: %w", err)
	}
	if obj.ID != "" {
		return obj.ID, nil
	}
	return obj.Name, nil
}

// scalarOrObjectIDs is scalarOrObjectID over a list, tolerating a mixed array.
func scalarOrObjectIDs(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, fmt.Errorf("expected an array: %w", err)
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		id, err := scalarOrObjectID(item)
		if err != nil {
			return nil, err
		}
		if id != "" {
			out = append(out, id)
		}
	}
	return out, nil
}

// Document is a simplified OpenVEX document.
type Document struct {
	Context    string      `json:"@context,omitempty"`
	ID         string      `json:"@id,omitempty"`
	Author     string      `json:"author,omitempty"`
	Timestamp  string      `json:"timestamp,omitempty"`
	Statements []Statement `json:"statements"`
}

// LoadVEX reads and parses a VEX document from the given path.
func LoadVEX(path string) (*Document, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading VEX document %s: %w", path, err)
	}

	var doc Document
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parsing VEX document %s: %w", path, err)
	}

	return &doc, nil
}

// ApplyVEX matches VEX statements to findings and updates their status
// accordingly. Match candidates per finding (in order):
//
//  1. The finding's RuleID (e.g. SEC-073, IAC-013, AI-PI-001). This
//     catches the `nox vex init` flow where every nox rule ID is a
//     valid waiver target.
//  2. The finding's Fingerprint, when the VEX statement carries a
//     matching _nox_fingerprint aux field — pins a waiver to a
//     specific occurrence rather than a whole rule class.
//  3. A retired rule ID the finding inherited, or the fingerprint that
//     retired rule would have produced here (see
//     findings.Finding.RetiredRuleIDs). Retiring a duplicate rule ID
//     must not un-waive what an operator already accepted under it.
//  4. (VULN-001 only) The CVE / GHSA identifiers in the finding's
//     vuln_id and aliases metadata. Operators can keep waiving by
//     CVE without learning nox-specific rule IDs.
//
// First match wins per finding.
func ApplyVEX(fs *findings.FindingSet, doc *Document) int {
	if doc == nil || len(doc.Statements) == 0 {
		return 0
	}

	stmtByID := make(map[string]Statement, len(doc.Statements))
	stmtByFingerprint := make(map[string]Statement)
	for i := range doc.Statements {
		stmt := doc.Statements[i]
		stmtByID[strings.ToUpper(stmt.VulnerabilityID)] = stmt
		if stmt.NoxFingerprint != "" {
			stmtByFingerprint[stmt.NoxFingerprint] = stmt
		}
	}

	applied := 0
	items := fs.Findings()
	for i := range items {
		f := &items[i]

		var matched *Statement
		// 1. Fingerprint pin (most specific).
		if stmt, ok := stmtByFingerprint[f.Fingerprint]; ok {
			matched = &stmt
		}
		// 2. Rule ID match (covers SEC-*, IAC-*, AI-*, etc.).
		if matched == nil {
			if stmt, ok := stmtByID[strings.ToUpper(f.RuleID)]; ok {
				matched = &stmt
			}
		}
		// 3. Waivers written against a rule ID that has since been retired
		//    into this one, by ID or by pinned fingerprint.
		if matched == nil {
			for _, id := range f.RetiredRuleIDs {
				if stmt, ok := stmtByID[strings.ToUpper(id)]; ok {
					matched = &stmt
					break
				}
			}
		}
		if matched == nil {
			for _, fp := range f.AliasFingerprints {
				if stmt, ok := stmtByFingerprint[fp]; ok {
					matched = &stmt
					break
				}
			}
		}
		// 4. CVE / GHSA aliases for VULN-001 findings.
		if matched == nil && f.RuleID == "VULN-001" {
			for _, id := range collectVulnIDs(f) {
				if stmt, ok := stmtByID[strings.ToUpper(id)]; ok {
					matched = &stmt
					break
				}
			}
		}

		if matched == nil {
			continue
		}
		switch matched.Status {
		case StatusNotAffected:
			fs.SetStatus(i, findings.StatusVEXNotAffected)
			applied++
		case StatusUnderInvestigation:
			fs.SetStatus(i, findings.StatusVEXUnderInvestigation)
			applied++
		case StatusFixed:
			fs.SetStatus(i, findings.StatusVEXFixed)
			applied++
		}
	}

	return applied
}

// StatusCounts tallies a VEX document's statements by status. It is the one
// histogram both Summary and the MCP vex_status tool project from, rather than
// each looping the statements separately.
func StatusCounts(doc *Document) map[Status]int {
	counts := make(map[Status]int)
	if doc == nil {
		return counts
	}
	for i := range doc.Statements {
		counts[doc.Statements[i].Status]++
	}
	return counts
}

// Summary returns a human-readable, deterministic summary of the VEX document.
func Summary(doc *Document) string {
	if doc == nil {
		return "no VEX document"
	}
	counts := StatusCounts(doc)
	// Emit in a stable status order — the old map iteration made this line
	// non-deterministic, which for a security artifact's summary is a defect.
	parts := make([]string, 0, len(counts))
	for _, status := range statusOrder {
		if n := counts[status]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, status))
		}
	}
	return fmt.Sprintf("VEX: %d statements (%s)", len(doc.Statements), strings.Join(parts, ", "))
}

// BuildStub generates a stub OpenVEX document containing one
// `under_investigation` statement per (RuleID, Fingerprint) pair found in the
// inputs. Operators triage by changing each statement's Status, adding a
// Justification / ImpactStatement, and committing the file. Subsequent scans
// can then diff against the document to detect new vs known findings.
//
// product is the SBOM-style identifier for the project (typically the Go
// module path or package name); when empty, statements omit the products
// field and operators must fill it in.
func BuildStub(items []findings.Finding, product string) *Document {
	type key struct {
		ruleID string
		fp     string
	}
	seen := map[key]int{} // pointer into doc.Statements
	doc := &Document{
		Context:    "https://openvex.dev/ns/v0.2.0",
		ID:         "nox-vex-init",
		Author:     "nox",
		Statements: []Statement{},
	}
	for i := range items {
		f := &items[i]
		k := key{ruleID: f.RuleID, fp: f.Fingerprint}
		if idx, ok := seen[k]; ok {
			doc.Statements[idx].NoxLocations = append(doc.Statements[idx].NoxLocations, locationLine(f))
			continue
		}
		stmt := Statement{
			VulnerabilityID: f.RuleID,
			Status:          StatusUnderInvestigation,
			NoxFingerprint:  f.Fingerprint,
			NoxLocations:    []string{locationLine(f)},
		}
		if product != "" {
			stmt.Products = []string{product}
		}
		seen[k] = len(doc.Statements)
		doc.Statements = append(doc.Statements, stmt)
	}
	return doc
}

func locationLine(f *findings.Finding) string {
	if f.Location.StartLine > 0 {
		return fmt.Sprintf("%s:%d", f.Location.FilePath, f.Location.StartLine)
	}
	return f.Location.FilePath
}

// collectVulnIDs extracts all vulnerability identifiers from a finding's metadata.
func collectVulnIDs(f *findings.Finding) []string {
	var ids []string
	if f.Metadata == nil {
		return ids
	}
	if vulnID := f.Metadata["vuln_id"]; vulnID != "" {
		ids = append(ids, vulnID)
	}
	if aliases := f.Metadata["aliases"]; aliases != "" {
		for _, a := range strings.Split(aliases, ",") {
			a = strings.TrimSpace(a)
			if a != "" {
				ids = append(ids, a)
			}
		}
	}
	return ids
}
