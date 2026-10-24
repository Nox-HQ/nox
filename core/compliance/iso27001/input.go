// Package iso27001 turns the evidence a nox scan already produced into
// supporting material for an ISO/IEC 27001:2022 assessment.
//
// It is deliberately small, offline and deterministic: it reads findings.json,
// an SBOM and the AI inventory, and never scans, never touches the network and
// never reads a clock. The same inputs produce the same bytes.
//
// It also deliberately cannot say that a control is met. An Annex A control is
// satisfied by an organisation operating a process, which a scanner cannot see;
// what a scan can offer is technical evidence that supports a control, and a
// precise list of what that evidence does not show. The Status vocabulary
// (see assess.go) describes the EVIDENCE, never the control, and a test pins
// that no rendered output uses a word that would claim otherwise.
package iso27001

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/nox-hq/nox/core/report"
)

// Artifact names one scan output the assessment relied on. Only the base name
// is kept: an absolute path would make the assessment differ between machines
// that hold byte-identical evidence.
type Artifact struct {
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	SHA256 string `json:"sha256"`
}

// SBOM is what the assessment needs from a software bill of materials.
type SBOM struct {
	Name       string
	Format     string
	Components int
}

// AIInventory is what the assessment needs from ai.inventory.json.
type AIInventory struct {
	Name           string
	Components     int
	Models         int
	UnpinnedModels int
	Checks         int
}

// Input is the evidence an assessment is derived from.
type Input struct {
	// Report is the scan's findings.json. Required.
	Report report.JSONReport
	// Artifacts lists every output relied on, findings first.
	Artifacts []Artifact
	// SBOM and AI are nil when the scan produced none, which is itself recorded:
	// an absent SBOM is a gap, not an empty one.
	SBOM *SBOM
	AI   *AIInventory
	// Commit is the repository revision the assessment was generated at. It may
	// be empty (not a git repository). It is not necessarily the revision the
	// scan ran at, and the artifact says so.
	Commit string
	// NoxVersion is the version of the nox that generates the assessment.
	NoxVersion string
}

// Digest returns the lowercase hex SHA-256 of data.
func Digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// ParseFindings decodes a findings.json.
func ParseFindings(name string, data []byte) (report.JSONReport, Artifact, error) {
	var rep report.JSONReport
	if err := json.Unmarshal(data, &rep); err != nil {
		return rep, Artifact{}, fmt.Errorf("%s is not a nox findings report: %w", name, err)
	}
	if rep.Meta.ToolName == "" {
		return rep, Artifact{}, fmt.Errorf("%s has no meta block; it is not a findings.json written by nox scan", name)
	}
	return rep, Artifact{Name: name, Kind: "findings", SHA256: Digest(data)}, nil
}

// ParseSBOM decodes a CycloneDX or SPDX JSON document and counts its
// components.
func ParseSBOM(name string, data []byte) (*SBOM, Artifact, error) {
	var doc struct {
		BomFormat  string            `json:"bomFormat"`
		SpecVer    string            `json:"specVersion"`
		SPDXVer    string            `json:"spdxVersion"`
		Components []json.RawMessage `json:"components"`
		Packages   []json.RawMessage `json:"packages"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, Artifact{}, fmt.Errorf("%s is not valid JSON: %w", name, err)
	}
	art := Artifact{Name: name, Kind: "sbom", SHA256: Digest(data)}
	switch {
	case doc.BomFormat == "CycloneDX":
		return &SBOM{Name: name, Format: "CycloneDX " + doc.SpecVer, Components: len(doc.Components)}, art, nil
	case doc.SPDXVer != "":
		return &SBOM{Name: name, Format: doc.SPDXVer, Components: len(doc.Packages)}, art, nil
	}
	return nil, Artifact{}, fmt.Errorf("%s is neither a CycloneDX nor an SPDX document", name)
}

// ParseAIInventory decodes an ai.inventory.json.
func ParseAIInventory(name string, data []byte) (*AIInventory, Artifact, error) {
	var doc struct {
		Components []json.RawMessage `json:"components"`
		Models     []struct {
			Pinned bool `json:"pinned"`
		} `json:"model_provenance"`
		Checks []string `json:"checks"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, Artifact{}, fmt.Errorf("%s is not valid JSON: %w", name, err)
	}
	inv := &AIInventory{Name: name, Components: len(doc.Components), Models: len(doc.Models), Checks: len(doc.Checks)}
	for _, m := range doc.Models {
		if !m.Pinned {
			inv.UnpinnedModels++
		}
	}
	return inv, Artifact{Name: name, Kind: "ai-inventory", SHA256: Digest(data)}, nil
}

// sortArtifacts orders artifacts findings-first, then by name, so the input
// order the caller happened to use never reaches the output.
func sortArtifacts(a []Artifact) {
	rank := map[string]int{"findings": 0, "sbom": 1, "ai-inventory": 2}
	sort.SliceStable(a, func(i, j int) bool {
		if rank[a[i].Kind] != rank[a[j].Kind] {
			return rank[a[i].Kind] < rank[a[j].Kind]
		}
		return a[i].Name < a[j].Name
	})
}
