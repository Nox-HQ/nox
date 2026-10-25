package threatmodel

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/nox-hq/nox/core/analyzers/ai"
	"github.com/nox-hq/nox/core/git"
	"github.com/nox-hq/nox/core/report"
)

// Dependency is one package from an SBOM.
type Dependency struct {
	Name    string
	Version string
}

// SBOM is what the model needs from a software bill of materials: the package
// names. It does not distinguish direct from transitive dependencies, because
// neither CycloneDX output nox writes records which is which, and the model
// says so wherever it relies on it.
type SBOM struct {
	Name       string
	Format     string
	Components []Dependency
}

// Input is the evidence a model is derived from.
type Input struct {
	// Report is the scan's findings.json. Required.
	Report report.JSONReport
	// Inventory is ai.inventory.json. Nil when the scan produced none, which
	// is recorded: an absent inventory is a gap, not an empty one.
	Inventory *ai.Inventory
	// SBOM is nil when none was provided; likewise a gap.
	SBOM *SBOM
	// Artifacts lists every output relied on, findings first.
	Artifacts []Artifact
	// Commit is the repository revision the model was generated at. It may be
	// empty (not a git repository).
	Commit string
	// NoxVersion is the version of the nox that generates the model.
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

// ParseInventory decodes an ai.inventory.json.
func ParseInventory(name string, data []byte) (*ai.Inventory, Artifact, error) {
	var inv ai.Inventory
	if err := json.Unmarshal(data, &inv); err != nil {
		return nil, Artifact{}, fmt.Errorf("%s is not valid JSON: %w", name, err)
	}
	return &inv, Artifact{Name: name, Kind: "ai-inventory", SHA256: Digest(data)}, nil
}

// ParseSBOM decodes a CycloneDX or SPDX JSON document into its package list.
func ParseSBOM(name string, data []byte) (*SBOM, Artifact, error) {
	var doc struct {
		BomFormat  string `json:"bomFormat"`
		SpecVer    string `json:"specVersion"`
		SPDXVer    string `json:"spdxVersion"`
		Components []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"components"`
		Packages []struct {
			Name        string `json:"name"`
			VersionInfo string `json:"versionInfo"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, Artifact{}, fmt.Errorf("%s is not valid JSON: %w", name, err)
	}
	art := Artifact{Name: name, Kind: "sbom", SHA256: Digest(data)}
	out := &SBOM{Name: name}
	switch {
	case doc.BomFormat == "CycloneDX":
		out.Format = "CycloneDX " + doc.SpecVer
		for _, c := range doc.Components {
			out.Components = append(out.Components, Dependency{Name: c.Name, Version: c.Version})
		}
	case doc.SPDXVer != "":
		out.Format = doc.SPDXVer
		for _, p := range doc.Packages {
			out.Components = append(out.Components, Dependency{Name: p.Name, Version: p.VersionInfo})
		}
	default:
		return nil, Artifact{}, fmt.Errorf("%s is neither a CycloneDX nor an SPDX document", name)
	}
	sort.SliceStable(out.Components, func(i, j int) bool {
		a, b := out.Components[i], out.Components[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Version < b.Version
	})
	return out, art, nil
}

// sortArtifacts orders artifacts findings-first, then by name, so the order the
// caller happened to use never reaches the output.
func sortArtifacts(a []Artifact) {
	rank := map[string]int{"findings": 0, "sbom": 1, "ai-inventory": 2}
	sort.SliceStable(a, func(i, j int) bool {
		if rank[a[i].Kind] != rank[a[j].Kind] {
			return rank[a[i].Kind] < rank[a[j].Kind]
		}
		return a[i].Name < a[j].Name
	})
}

// Paths says where the scan outputs are. Empty fields take the defaults the
// scan writes: findings.json, sbom.cdx.json (then sbom.spdx.json) and
// ai.inventory.json under Dir.
type Paths struct {
	Dir       string
	Findings  string
	SBOM      string
	Inventory string
	// Repo is where to read the commit from when the scan outputs are kept
	// elsewhere; default Dir.
	Repo string
}

// Load reads the scan outputs a model is built from. Only findings.json is
// required: an absent SBOM or AI inventory is recorded in the model as a gap,
// because a scan scoped away from dependencies or AI legitimately has none.
func Load(p Paths, noxVersion string) (Input, error) {
	in := Input{NoxVersion: noxVersion}
	dir := p.Dir
	if dir == "" {
		dir = "."
	}
	findingsPath := p.Findings
	if findingsPath == "" {
		findingsPath = filepath.Join(dir, "findings.json")
	}
	raw, err := os.ReadFile(findingsPath) //nolint:gosec // caller-supplied scan artifact
	if err != nil {
		if os.IsNotExist(err) {
			return in, fmt.Errorf("no scan output at %s; run `nox scan %s --format json,cdx` first, then run this again", findingsPath, dir)
		}
		return in, err
	}
	rep, art, err := ParseFindings(filepath.Base(findingsPath), raw)
	if err != nil {
		return in, err
	}
	in.Report = rep
	in.Artifacts = append(in.Artifacts, art)

	sbomPath := p.SBOM
	if sbomPath == "" {
		sbomPath = firstExisting(filepath.Join(dir, "sbom.cdx.json"), filepath.Join(dir, "sbom.spdx.json"))
	}
	if sbomPath != "" {
		data, err := os.ReadFile(sbomPath) //nolint:gosec // caller-supplied scan artifact
		if err != nil {
			return in, err
		}
		s, sa, err := ParseSBOM(filepath.Base(sbomPath), data)
		if err != nil {
			return in, err
		}
		in.SBOM = s
		in.Artifacts = append(in.Artifacts, sa)
	}

	invPath := p.Inventory
	if invPath == "" {
		invPath = firstExisting(filepath.Join(dir, "ai.inventory.json"))
	}
	if invPath != "" {
		data, err := os.ReadFile(invPath) //nolint:gosec // caller-supplied scan artifact
		if err != nil {
			return in, err
		}
		inv, ia, err := ParseInventory(filepath.Base(invPath), data)
		if err != nil {
			return in, err
		}
		in.Inventory = inv
		in.Artifacts = append(in.Artifacts, ia)
	}

	// The revision is best-effort provenance. Outside a git repository the
	// model simply omits it.
	repo := p.Repo
	if repo == "" {
		repo = dir
	}
	if c, err := git.HeadCommit(repo); err == nil {
		in.Commit = c
	}
	return in, nil
}

// LoadPrevious reads a model.json written by an earlier run. Anything that is
// not a threat model is an error, never an empty model: "no earlier model" and
// "an earlier model with nothing in it" must stay different.
func LoadPrevious(path string) (Model, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // caller-supplied earlier model
	if err != nil {
		return Model{}, err
	}
	var m Model
	if err := json.Unmarshal(raw, &m); err != nil {
		return Model{}, fmt.Errorf("%s is not a nox threat model: %w", path, err)
	}
	if m.Meta.Report != ReportKind {
		return Model{}, fmt.Errorf("%s is not a nox threat model (report kind %q); pass the model.json that `nox model` wrote", path, m.Meta.Report)
	}
	return m, nil
}

// BuildAgainst builds the model for in and, when previous names an earlier
// model.json, says what changed since it. It is the one place that pairing is
// made, so `nox model --previous` and the MCP threat_model tool cannot compare
// differently. An empty previous builds the model alone.
func BuildAgainst(in Input, previous string) (Model, error) {
	m := Build(in)
	if previous == "" {
		return m, nil
	}
	prev, err := LoadPrevious(previous)
	if err != nil {
		return Model{}, err
	}
	return m.WithChanges(prev), nil
}

func firstExisting(paths ...string) string {
	for _, p := range paths {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}
