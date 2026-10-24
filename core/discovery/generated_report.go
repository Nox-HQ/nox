package discovery

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// reportSniffBytes is how much of a candidate file is read to decide whether
// it might be a nox report. Every nox writer puts its producer marker within
// the first few hundred bytes; 8 KiB leaves room for the HTML report's
// stylesheet, which sits between its <title> and its <h1>.
const reportSniffBytes = 8 << 10

// Producer markers, matched against the sniffed prefix only. A match is a
// reason to look closer, never a decision: each one is confirmed by decoding
// the document and checking the field it claims to be in (see confirmReport).
var sniffSARIF = regexp.MustCompile(`"driver"\s*:\s*\{\s*"name"\s*:\s*"nox"`)

var sniffMeta = regexp.MustCompile(`"tool_name"\s*:\s*"nox"`)

var sniffCDX = regexp.MustCompile(`"bomFormat"\s*:\s*"CycloneDX"`)

var sniffSPDX = regexp.MustCompile(`"Tool: nox-`)

var sniffPlan = regexp.MustCompile(`"schema_version"\s*:\s*"attack-plan/`)

var sniffName = regexp.MustCompile(`"name"\s*:\s*"nox"`)

const htmlReportTitle = "<title>Nox Security Report</title>"
const htmlReportHeading = "<h1>Nox Security Report</h1>"

// GeneratedReport reports whether the file at path is a report nox itself
// wrote, and if so which kind. A scan does not read such a file as source.
//
// A report is nox's own words: rule descriptions, finding messages, evidence
// summaries. Read back as source, that prose matches the rules it describes —
// a SARIF rule catalog fires AI-009 on the description of AI-009 — so every
// kept copy of an old run adds findings about nox to a scan of the project.
// ScanOptions.OutputDir already skips the report a scan is about to overwrite;
// this covers every other copy, which is where they usually are: a renamed
// output directory, a downloaded CI artifact, a committed results.sarif.
//
// The decision is made on content, never on a name or a path, so it must not
// claim a file that is not a nox report. Two things hold that line:
//
//   - The producer marker has to be in the first reportSniffBytes, in the
//     shape the writer emits it. Most files are rejected here without being
//     read past the prefix, and files of other types are not opened at all.
//   - The document is then decoded and the marker checked at its real path:
//     SARIF runs[].tool.driver.name, findings.json/evidence meta.tool_name,
//     CycloneDX metadata.tools[].name, SPDX creationInfo.creators, an attack
//     plan's top-level schema_version. The HTML report, which is not
//     structured data, needs both its <title> and its <h1>. A file that only
//     mentions nox, or does not parse, is scanned.
//
// What is deliberately NOT recognised: another tool's SARIF or SBOM (a
// scanner's SARIF can carry what it matched, verbatim — a committed credential
// in a gitleaks report is still a committed credential), a SARIF that merges a
// nox run with any other tool's, vex.json (an input the project edits and
// owns, even when `nox vex init` started it), and ai.inventory.json (it names
// no producer, so there is nothing to confirm).
func GeneratedReport(path string) (string, bool) {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".json", ".sarif", ".html", ".htm":
	default:
		return "", false
	}
	f, err := os.Open(path) //nolint:gosec // path comes from the scan walk
	if err != nil {
		return "", false
	}
	defer func() { _ = f.Close() }()

	head := make([]byte, reportSniffBytes)
	n, err := io.ReadFull(f, head)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return "", false
	}
	head = head[:n]

	if ext == ".html" || ext == ".htm" {
		if bytes.Contains(head, []byte(htmlReportTitle)) && bytes.Contains(head, []byte(htmlReportHeading)) {
			return "HTML report", true
		}
		return "", false
	}

	kind := sniffJSONReport(head)
	if kind == "" {
		return "", false
	}
	if !confirmReport(kind, io.MultiReader(bytes.NewReader(head), f)) {
		return "", false
	}
	return kind, true
}

// sniffJSONReport returns the report kind whose marker appears in the prefix
// of a JSON object, or "" when none does.
func sniffJSONReport(head []byte) string {
	trimmed := bytes.TrimLeft(bytes.TrimPrefix(head, []byte("\xef\xbb\xbf")), " \t\r\n")
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return ""
	}
	switch {
	case sniffSARIF.Match(head):
		return "SARIF"
	case sniffMeta.Match(head):
		return "nox JSON report"
	case sniffCDX.Match(head) && sniffName.Match(head):
		return "CycloneDX SBOM"
	case sniffSPDX.Match(head):
		return "SPDX SBOM"
	case sniffPlan.Match(head):
		return "attack plan"
	}
	return ""
}

// reportProbe decodes only the fields that name a report's producer. Every
// other field, including a SARIF file's results, is skipped by the decoder.
//
// The fields of all kinds share one struct, so a field one kind types
// differently from another is held raw: CycloneDX's top-level "version" is a
// number where SARIF's is a string, and a type mismatch fails the decode.
type reportProbe struct {
	Version json.RawMessage `json:"version"`
	Runs    []struct {
		Tool struct {
			Driver struct {
				Name string `json:"name"`
			} `json:"driver"`
		} `json:"tool"`
	} `json:"runs"`
	Meta *struct {
		ToolName      string `json:"tool_name"`
		SchemaVersion string `json:"schema_version"`
	} `json:"meta"`
	BOMFormat string `json:"bomFormat"`
	Metadata  *struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	} `json:"metadata"`
	SPDXVersion  string `json:"spdxVersion"`
	CreationInfo *struct {
		Creators []string `json:"creators"`
	} `json:"creationInfo"`
	// An attack plan names no tool. Its schema version is nox's own, and
	// "assets" is its first section.
	SchemaVersion string `json:"schema_version"`

	Assets json.RawMessage `json:"assets"`
}

// confirmReport decodes the document and checks that the producer marker the
// prefix suggested is where that kind of report puts it.
func confirmReport(kind string, r io.Reader) bool {
	var p reportProbe
	if err := json.NewDecoder(r).Decode(&p); err != nil {
		return false
	}
	switch kind {
	case "SARIF":
		return confirmSARIF(&p)
	case "nox JSON report":
		return p.Meta != nil && p.Meta.ToolName == "nox" && p.Meta.SchemaVersion != ""
	case "CycloneDX SBOM":
		return confirmCycloneDX(&p)
	case "SPDX SBOM":
		return confirmSPDX(&p)
	case "attack plan":
		return strings.HasPrefix(p.SchemaVersion, "attack-plan/") && len(p.Assets) > 0
	}
	return false
}

// confirmSARIF requires every run to be nox's. A file that merges a nox run
// with another tool's carries that tool's words too, and those are not ours to
// skip.
func confirmSARIF(p *reportProbe) bool {
	var version string
	if err := json.Unmarshal(p.Version, &version); err != nil || !strings.HasPrefix(version, "2.") || len(p.Runs) == 0 {
		return false
	}
	for _, run := range p.Runs {
		if run.Tool.Driver.Name != "nox" {
			return false
		}
	}
	return true
}

func confirmCycloneDX(p *reportProbe) bool {
	if p.BOMFormat != "CycloneDX" || p.Metadata == nil {
		return false
	}
	for _, t := range p.Metadata.Tools {
		if t.Name == "nox" {
			return true
		}
	}
	return false
}

func confirmSPDX(p *reportProbe) bool {
	if !strings.HasPrefix(p.SPDXVersion, "SPDX-") || p.CreationInfo == nil {
		return false
	}
	for _, c := range p.CreationInfo.Creators {
		if strings.HasPrefix(c, "Tool: nox-") {
			return true
		}
	}
	return false
}
