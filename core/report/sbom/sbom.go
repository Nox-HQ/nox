// Package sbom generates CycloneDX and SPDX SBOM documents from a dependency
// package inventory. Both generators produce deterministic JSON output suitable
// for ingestion by vulnerability scanners and compliance tools.
package sbom

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/nox-hq/nox/core/analyzers/ai"
	"github.com/nox-hq/nox/core/analyzers/deps"
	"github.com/nox-hq/nox/core/image"
	"github.com/nox-hq/nox/core/report"
)

// ---------------------------------------------------------------------------
// CycloneDX 1.5 JSON
// ---------------------------------------------------------------------------

// CDXReport is the top-level CycloneDX BOM structure.
type CDXReport struct {
	BOMFormat    string         `json:"bomFormat"`
	SpecVersion  string         `json:"specVersion"`
	SerialNumber string         `json:"serialNumber"`
	Version      int            `json:"version"`
	Metadata     CDXMetadata    `json:"metadata"`
	Components   []CDXComponent `json:"components"`
	// Dependencies is set for an artifact's BOM: the artifact depends on each
	// component it contains.
	Dependencies    []CDXDependency    `json:"dependencies,omitempty"`
	Vulnerabilities []CDXVulnerability `json:"vulnerabilities,omitempty"`
}

// CDXDependency says one component depends on others, by bom-ref.
type CDXDependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
}

// CDXHash is a component's digest.
type CDXHash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

// CDXMetadata holds tool and timestamp information.
type CDXMetadata struct {
	Timestamp string    `json:"timestamp"`
	Tools     []CDXTool `json:"tools"`
	// Component is what the BOM describes, for an artifact's BOM: the
	// artifact, named, with its digest.
	Component *CDXComponent `json:"component,omitempty"`
}

// CDXTool identifies the tool that generated the BOM.
type CDXTool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

// CDXLicense represents a license in CycloneDX format.
type CDXLicense struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

// CDXLicenseWrapper wraps a CDXLicense for the CycloneDX licenses array.
type CDXLicenseWrapper struct {
	License CDXLicense `json:"license"`
}

// CDXComponent represents a single dependency or machine-learning model.
type CDXComponent struct {
	Type   string `json:"type"`
	BOMRef string `json:"bom-ref"`
	// Publisher is the model provider for a machine-learning-model component.
	Publisher string `json:"publisher,omitempty"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	// PURL is omitted when the component has no package-URL type, as a model
	// served by an API provider has none.
	PURL     string              `json:"purl,omitempty"`
	Hashes   []CDXHash           `json:"hashes,omitempty"`
	Licenses []CDXLicenseWrapper `json:"licenses,omitempty"`
}

// CDXVulnerability represents a known vulnerability in the CycloneDX format.
type CDXVulnerability struct {
	ID          string      `json:"id"`
	Source      CDXSource   `json:"source"`
	Ratings     []CDXRating `json:"ratings,omitempty"`
	Description string      `json:"description,omitempty"`
	Affects     []CDXAffect `json:"affects"`
	// Analysis is set when nox decided the vulnerability does not affect
	// this product (see WithFindings).
	Analysis *CDXAnalysis `json:"analysis,omitempty"`
}

// CDXSource identifies the vulnerability database source.
type CDXSource struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

// CDXRating holds a severity rating for a vulnerability.
type CDXRating struct {
	Severity string `json:"severity"`
}

// CDXAffect identifies a component affected by a vulnerability.
type CDXAffect struct {
	Ref string `json:"ref"`
}

// CycloneDXReporter generates CycloneDX 1.5 JSON SBOMs.
type CycloneDXReporter struct {
	ToolVersion string
	// aiInventory supplies the machine-learning-model components (the
	// ML-BOM). Nil writes a dependency-only SBOM.
	aiInventory *ai.Inventory
	// verdicts are the not-impacting decisions from the scan's findings,
	// written as each vulnerability's analysis. Nil writes none.
	verdicts map[verdictKey]*CDXAnalysis
	// subject is the artifact the BOM describes. Zero for a scan's BOM.
	subject spdxSubject
}

// cdxSubjectRef is the subject's bom-ref.
const cdxSubjectRef = "subject"

// WithSubject makes the BOM describe one artifact, such as a release archive:
// metadata.component names it with its SHA-256, it depends on each component,
// and the serial number derives from its digest.
func (r *CycloneDXReporter) WithSubject(name, sha256Hex string) *CycloneDXReporter {
	r.subject = spdxSubject{name: name, sha256: sha256Hex}
	return r
}

// NewCycloneDXReporter returns a reporter configured with the given tool version.
func NewCycloneDXReporter(version string) *CycloneDXReporter {
	return &CycloneDXReporter{ToolVersion: version}
}

// WithAIInventory adds the models in inv to the BOM as machine-learning-model
// components, one per distinct model: the same set the scan summary counts, so
// the console and the ML-BOM cannot disagree about which models an app uses.
func (r *CycloneDXReporter) WithAIInventory(inv *ai.Inventory) *CycloneDXReporter {
	r.aiInventory = inv
	return r
}

// modelComponents renders the AI inventory's distinct models as CycloneDX
// machine-learning-model components, in DistinctModels' deterministic order.
func (r *CycloneDXReporter) modelComponents() []CDXComponent {
	models := r.aiInventory.DistinctModels()
	out := make([]CDXComponent, 0, len(models))
	for i, m := range models {
		comp := CDXComponent{
			Type:    "machine-learning-model",
			BOMRef:  fmt.Sprintf("model:%d", i),
			Name:    m.Name,
			Version: m.Version,
			PURL:    modelPURL(m),
		}
		if m.Registry != "" && m.Registry != "unknown" {
			comp.Publisher = m.Registry
		}
		if m.License != "" {
			comp.Licenses = []CDXLicenseWrapper{{License: cdxLicenseFor(m.License)}}
		}
		out = append(out, comp)
	}
	return out
}

// modelPURL returns a package URL for a model when its registry has a purl
// type. Only Hugging Face does; an API provider's model has no package URL.
func modelPURL(m ai.ModelReference) string {
	if m.Registry != "huggingface" {
		return ""
	}
	name := strings.TrimPrefix(m.Name, "https://huggingface.co/")
	if m.Version == "" {
		return "pkg:huggingface/" + name
	}
	return "pkg:huggingface/" + name + "@" + m.Version
}

// Generate produces a CycloneDX JSON byte slice from the package inventory.
func (r *CycloneDXReporter) Generate(inventory *deps.PackageInventory) ([]byte, error) {
	pkgs := inventory.Packages()

	// Build a map from original index to package for vulnerability lookup.
	// We need to track original indices through sorting.
	type indexedPkg struct {
		pkg     deps.Package
		origIdx int
	}
	indexed := make([]indexedPkg, len(pkgs))
	for i, p := range pkgs {
		indexed[i] = indexedPkg{pkg: p, origIdx: i}
	}

	// Sort deterministically by ecosystem, then name, then version.
	sort.Slice(indexed, func(i, j int) bool {
		a, b := indexed[i].pkg, indexed[j].pkg
		if a.Ecosystem != b.Ecosystem {
			return a.Ecosystem < b.Ecosystem
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Version < b.Version
	})

	components := make([]CDXComponent, 0, len(indexed))
	bomRefs := make(map[int]string) // origIdx -> bom-ref
	for i, ip := range indexed {
		bomRef := fmt.Sprintf("pkg:%d", i)
		bomRefs[ip.origIdx] = bomRef
		comp := CDXComponent{
			Type:    "library",
			BOMRef:  bomRef,
			Name:    ip.pkg.Name,
			Version: ip.pkg.Version,
			PURL:    buildPURL(ip.pkg),
		}
		if ip.pkg.License != "" {
			comp.Licenses = []CDXLicenseWrapper{{License: cdxLicenseFor(ip.pkg.License)}}
		}
		components = append(components, comp)
	}
	components = append(components, r.modelComponents()...)

	// Build vulnerability entries from inventory.
	allVulns := inventory.AllVulnerabilities()
	var cdxVulns []CDXVulnerability
	if allVulns != nil {
		// Collect and sort for deterministic output.
		type vulnEntry struct {
			origIdx int
			vuln    deps.Vulnerability
			pkg     deps.Package
		}
		var entries []vulnEntry
		for idx, vulns := range allVulns {
			for _, v := range vulns {
				entries = append(entries, vulnEntry{origIdx: idx, vuln: v, pkg: pkgs[idx]})
			}
		}
		sort.Slice(entries, func(i, j int) bool {
			// Sort by vuln.ID first, then by the package's original index as a
			// deterministic tie-breaker. Entries are collected by ranging a map
			// (randomized order in Go), so when one CVE affects several packages
			// its entries share an equal vuln.ID; without this tie-breaker their
			// relative order would vary run to run, breaking nox's byte-identical
			// output guarantee.
			if entries[i].vuln.ID != entries[j].vuln.ID {
				return entries[i].vuln.ID < entries[j].vuln.ID
			}
			return entries[i].origIdx < entries[j].origIdx
		})

		for _, e := range entries {
			ref, ok := bomRefs[e.origIdx]
			if !ok {
				continue
			}
			cdxVuln := CDXVulnerability{
				ID: e.vuln.ID,
				Source: CDXSource{
					Name: "OSV",
					URL:  "https://osv.dev/vulnerability/" + e.vuln.ID,
				},
				Description: e.vuln.Summary,
				Affects:     []CDXAffect{{Ref: ref}},
				Analysis:    r.analysisFor(e.pkg, e.vuln),
			}
			if e.vuln.Severity != "" {
				cdxVuln.Ratings = []CDXRating{{Severity: string(e.vuln.Severity)}}
			}
			cdxVulns = append(cdxVulns, cdxVuln)
		}
	}

	serial := deterministicSerialURN(components)
	var subject *CDXComponent
	var dependencies []CDXDependency
	if r.subject.name != "" {
		subject = &CDXComponent{
			Type:    "file",
			BOMRef:  cdxSubjectRef,
			Name:    r.subject.name,
			Version: "",
			Hashes:  []CDXHash{{Alg: "SHA-256", Content: r.subject.sha256}},
		}
		refs := make([]string, 0, len(components))
		for i := range components {
			refs = append(refs, components[i].BOMRef)
		}
		dependencies = []CDXDependency{{Ref: cdxSubjectRef, DependsOn: refs}}
		serial = serialFromDigest(r.subject.sha256)
	}

	doc := CDXReport{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.5",
		SerialNumber: serial,
		Version:      1,
		Metadata: CDXMetadata{
			Timestamp: report.GeneratedAt(),
			Tools: []CDXTool{
				{
					Vendor:  "nox",
					Name:    "nox",
					Version: r.ToolVersion,
				},
			},
		},
		Components:      components,
		Dependencies:    dependencies,
		Vulnerabilities: cdxVulns,
	}
	doc.Metadata.Component = subject

	return json.MarshalIndent(doc, "", "  ")
}

// WriteToFile generates the CycloneDX report and writes it to the given path.
func (r *CycloneDXReporter) WriteToFile(inventory *deps.PackageInventory, path string) error {
	data, err := r.Generate(inventory)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// ---------------------------------------------------------------------------
// SPDX 2.3 JSON
// ---------------------------------------------------------------------------

// SPDXDocument is the top-level SPDX document structure.
type SPDXDocument struct {
	SPDXVersion       string             `json:"spdxVersion"`
	DataLicense       string             `json:"dataLicense"`
	SPDXID            string             `json:"SPDXID"`
	Name              string             `json:"name"`
	DocumentNamespace string             `json:"documentNamespace"`
	CreationInfo      SPDXCreationInfo   `json:"creationInfo"`
	Packages          []SPDXPackage      `json:"packages"`
	Relationships     []SPDXRelationship `json:"relationships"`
}

// SPDXCreationInfo contains creation metadata.
type SPDXCreationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

// SPDXPackage represents a single package in the SPDX document.
type SPDXPackage struct {
	SPDXID           string            `json:"SPDXID"`
	Name             string            `json:"name"`
	VersionInfo      string            `json:"versionInfo"`
	DeclaredLicense  string            `json:"licenseDeclared"`
	DownloadLocation string            `json:"downloadLocation"`
	FilesAnalyzed    bool              `json:"filesAnalyzed"`
	Checksums        []SPDXChecksum    `json:"checksums,omitempty"`
	PrimaryPurpose   string            `json:"primaryPackagePurpose,omitempty"`
	ExternalRefs     []SPDXExternalRef `json:"externalRefs,omitempty"`
}

// SPDXChecksum is a package checksum.
type SPDXChecksum struct {
	Algorithm     string `json:"algorithm"`
	ChecksumValue string `json:"checksumValue"`
}

// spdxSubjectID is the SPDX element for the artifact a document describes.
const spdxSubjectID = "SPDXRef-Subject"

// SPDXExternalRef is a reference to an external resource.
type SPDXExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

// SPDXRelationship describes a relationship between SPDX elements.
type SPDXRelationship struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelationshipType   string `json:"relationshipType"`
	RelatedSPDXElement string `json:"relatedSpdxElement"`
}

// SPDXReporter generates SPDX 2.3 JSON SBOMs.
type SPDXReporter struct {
	ToolVersion string
	subject     *spdxSubject
}

type spdxSubject struct{ name, sha256 string }

// WithSubject makes the document describe one artifact, such as a release
// archive: it is named after the artifact, the artifact is a package carrying
// its SHA-256, and every inventoried package is CONTAINED by it. Without a
// subject the document describes the packages themselves, as a scan of a
// working tree does.
func (r *SPDXReporter) WithSubject(name, sha256Hex string) *SPDXReporter {
	r.subject = &spdxSubject{name: name, sha256: sha256Hex}
	return r
}

// NewSPDXReporter returns a reporter configured with the given tool version.
func NewSPDXReporter(version string) *SPDXReporter {
	return &SPDXReporter{ToolVersion: version}
}

// Generate produces an SPDX 2.3 JSON byte slice from the package inventory.
func (r *SPDXReporter) Generate(inventory *deps.PackageInventory) ([]byte, error) {
	pkgs := inventory.Packages()

	// Build a map from original index to package for vulnerability lookup.
	type indexedPkg struct {
		pkg     deps.Package
		origIdx int
	}
	indexed := make([]indexedPkg, len(pkgs))
	for i, p := range pkgs {
		indexed[i] = indexedPkg{pkg: p, origIdx: i}
	}

	// Sort deterministically.
	sort.Slice(indexed, func(i, j int) bool {
		a, b := indexed[i].pkg, indexed[j].pkg
		if a.Ecosystem != b.Ecosystem {
			return a.Ecosystem < b.Ecosystem
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Version < b.Version
	})

	allVulns := inventory.AllVulnerabilities()

	spdxPkgs := make([]SPDXPackage, 0, len(indexed))
	relationships := make([]SPDXRelationship, 0, len(indexed))

	for i, ip := range indexed {
		spdxID := fmt.Sprintf("SPDXRef-Package-%d", i)
		purl := buildPURL(ip.pkg)

		// SPDX 2.3 requires licenseDeclared to be a valid SPDX license
		// expression, NOASSERTION, or NONE. Free-text like "Apache 2.0" (with a
		// space) or "see LICENSE file" would produce a spec-invalid document, so
		// only emit the license when it is a recognized SPDX identifier and fall
		// back to NOASSERTION otherwise. This mirrors the CycloneDX path's use of
		// the spdxLicenseIDs whitelist.
		declaredLicense := "NOASSERTION"
		if spdxLicenseIDs[ip.pkg.License] {
			declaredLicense = ip.pkg.License
		}

		pkg := SPDXPackage{
			SPDXID:           spdxID,
			Name:             ip.pkg.Name,
			VersionInfo:      ip.pkg.Version,
			DeclaredLicense:  declaredLicense,
			DownloadLocation: "NOASSERTION",
			FilesAnalyzed:    false,
		}

		var refs []SPDXExternalRef
		if purl != "" {
			refs = append(refs, SPDXExternalRef{
				ReferenceCategory: "PACKAGE-MANAGER",
				ReferenceType:     "purl",
				ReferenceLocator:  purl,
			})
		}

		// Add SECURITY external refs for known vulnerabilities.
		if allVulns != nil {
			vulns := allVulns[ip.origIdx]
			// Sort vuln IDs for deterministic output.
			sortedVulns := make([]deps.Vulnerability, len(vulns))
			copy(sortedVulns, vulns)
			sort.Slice(sortedVulns, func(a, b int) bool {
				return sortedVulns[a].ID < sortedVulns[b].ID
			})
			for _, v := range sortedVulns {
				refs = append(refs, SPDXExternalRef{
					ReferenceCategory: "SECURITY",
					ReferenceType:     "advisory",
					ReferenceLocator:  "https://osv.dev/vulnerability/" + v.ID,
				})
			}
		}

		if len(refs) > 0 {
			pkg.ExternalRefs = refs
		}

		spdxPkgs = append(spdxPkgs, pkg)

		rel := SPDXRelationship{SPDXElementID: "SPDXRef-DOCUMENT", RelationshipType: "DESCRIBES", RelatedSPDXElement: spdxID}
		if r.subject != nil {
			rel = SPDXRelationship{SPDXElementID: spdxSubjectID, RelationshipType: "CONTAINS", RelatedSPDXElement: spdxID}
		}
		relationships = append(relationships, rel)
	}

	name, namespace := "nox-scan", spdxNamespace("scan", spdxPkgs)
	if s := r.subject; s != nil {
		name = s.name
		// The artifact's digest identifies it, which is what the namespace is for.
		namespace = "https://github.com/nox-hq/nox/spdx/" + s.sha256
		spdxPkgs = append([]SPDXPackage{{
			SPDXID:           spdxSubjectID,
			Name:             s.name,
			VersionInfo:      "NOASSERTION",
			DeclaredLicense:  "NOASSERTION",
			DownloadLocation: "NOASSERTION",
			Checksums:        []SPDXChecksum{{Algorithm: "SHA256", ChecksumValue: s.sha256}},
			PrimaryPurpose:   "ARCHIVE",
		}}, spdxPkgs...)
		relationships = append([]SPDXRelationship{{
			SPDXElementID: "SPDXRef-DOCUMENT", RelationshipType: "DESCRIBES", RelatedSPDXElement: spdxSubjectID,
		}}, relationships...)
	}

	doc := SPDXDocument{
		SPDXVersion:       "SPDX-2.3",
		DataLicense:       "CC0-1.0",
		SPDXID:            "SPDXRef-DOCUMENT",
		Name:              name,
		DocumentNamespace: namespace,
		CreationInfo: SPDXCreationInfo{
			Created:  report.GeneratedAt(),
			Creators: []string{fmt.Sprintf("Tool: nox-%s", r.ToolVersion)},
		},
		Packages:      spdxPkgs,
		Relationships: relationships,
	}

	return json.MarshalIndent(doc, "", "  ")
}

// WriteToFile generates the SPDX report and writes it to the given path.
func (r *SPDXReporter) WriteToFile(inventory *deps.PackageInventory, path string) error {
	data, err := r.Generate(inventory)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

// purlEcosystems maps internal ecosystem names to PURL type prefixes.
var purlEcosystems = map[string]string{
	"go":        "golang",
	"npm":       "npm",
	"pypi":      "pypi",
	"rubygems":  "gem",
	"cargo":     "cargo",
	"maven":     "maven",
	"gradle":    "maven",
	"nuget":     "nuget",
	"composer":  "composer",
	"packagist": "composer",
	"pub":       "pub",
	"hex":       "hex",
	"swift":     "swift",
	"cocoapods": "cocoapods",
	"conan":     "conan",
}

// buildPURL constructs a Package URL (purl) for the given package.
// See https://github.com/package-url/purl-spec for the format.
func buildPURL(p deps.Package) string {
	if purl, ok := distroPURL(p); ok {
		return purl
	}
	if p.Ecosystem == "docker" {
		return dockerPURL(p)
	}
	purlType, ok := purlEcosystems[p.Ecosystem]
	if !ok {
		return ""
	}
	version := purlVersion(p.Version)
	// Maven PURLs use namespace/name format for groupId:artifactId.
	if (p.Ecosystem == "maven" || p.Ecosystem == "gradle") && strings.Contains(p.Name, ":") {
		parts := strings.SplitN(p.Name, ":", 2)
		return fmt.Sprintf("pkg:%s/%s/%s@%s", purlType, parts[0], parts[1], version)
	}
	return fmt.Sprintf("pkg:%s/%s@%s", purlType, p.Name, version)
}

// distroPURL is the purl of a distribution package read from an image
// ("alpine:v3.22", "debian:12", "ubuntu:24.04:LTS"). nox records the source
// package, which advisories name, so arch is "source"; distro names the
// release.
func distroPURL(p deps.Package) (string, bool) {
	name, release, ok := strings.Cut(p.Ecosystem, ":")
	if !ok {
		return "", false
	}
	release, _, _ = strings.Cut(release, ":") // "24.04:LTS" -> "24.04"
	var purlType string
	switch name {
	case "alpine":
		purlType, release = "apk", strings.TrimPrefix(release, "v")
	case "debian", "ubuntu":
		purlType = "deb"
	default:
		return "", false
	}
	return fmt.Sprintf("pkg:%s/%s/%s@%s?arch=source&distro=%s-%s", purlType, name, p.Name, purlVersion(p.Version), name, release), true
}

// dockerPURL is the purl of a base image: Docker Hub's official images live
// under library/, and another registry is named by repository_url.
func dockerPURL(p deps.Package) string {
	ref := image.ParseRef(p.Name)
	purl := fmt.Sprintf("pkg:docker/%s@%s", ref.Repository, purlVersion(p.Version))
	if ref.Registry != "registry-1.docker.io" {
		purl += "?repository_url=" + ref.Registry
	}
	return purl
}

// purlVersion percent-encodes a version as the purl spec requires: "+" in
// 2.36-9+deb12u14 is %2B, while ":" (a dpkg epoch, a digest's algorithm)
// stays.
func purlVersion(v string) string {
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte(".-_~:", c) >= 0 {
			b.WriteByte(c)
			continue
		}
		fmt.Fprintf(&b, "%%%02X", c)
	}
	return b.String()
}

// spdxNamespace derives a document namespace from the package set. SPDX 2.3
// requires the namespace to be unique per document; the constant nox used
// before made every nox SBOM claim the same identity. A content hash keeps
// output reproducible, like deterministicSerialURN does for CycloneDX.
func spdxNamespace(kind string, pkgs []SPDXPackage) string {
	h := sha256.New()
	for i := range pkgs {
		_, _ = fmt.Fprintf(h, "%s\x00%s\n", pkgs[i].Name, pkgs[i].VersionInfo)
		for _, ref := range pkgs[i].ExternalRefs {
			_, _ = fmt.Fprintf(h, "\x00%s", ref.ReferenceLocator)
		}
	}
	return fmt.Sprintf("https://github.com/nox-hq/nox/spdx/%s-%x", kind, h.Sum(nil))
}

// deterministicSerialURN returns a valid RFC-4122 UUID URN derived from the
// component set. CycloneDX constrains serialNumber to the UUID URN grammar, so
// the previous constant "urn:uuid:nox-scan" failed schema validation on every
// document. Deriving it from a content hash keeps nox's reproducible-output
// guarantee — identical input yields an identical serial — while remaining a
// well-formed, per-scan-unique UUID.
func deterministicSerialURN(components []CDXComponent) string {
	h := sha256.New()
	for i := range components {
		_, _ = fmt.Fprintf(h, "%s\x00%s\x00%s\n", components[i].Name, components[i].Version, components[i].PURL)
	}
	return uuidURNFrom(h.Sum(nil))
}

// serialFromDigest is an artifact BOM's serial: the artifact's own digest as a
// UUID, so one file always gets the same serial and two files never share one.
func serialFromDigest(sha256Hex string) string {
	h := sha256.Sum256([]byte("nox-artifact-bom\x00" + sha256Hex))
	return uuidURNFrom(h[:])
}

func uuidURNFrom(sum []byte) string {
	// Format 16 bytes as a UUID, stamping the version (4) and variant (RFC 4122)
	// nibbles so the result is a syntactically valid UUID.
	var u [16]byte
	copy(u[:], sum)
	u[6] = (u[6] & 0x0f) | 0x40
	u[8] = (u[8] & 0x3f) | 0x80
	return fmt.Sprintf("urn:uuid:%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
}

// spdxLicenseIDs is the set of SPDX identifiers common in real dependency
// metadata. CycloneDX validates license.id against the SPDX enumeration, so an
// arbitrary string there (e.g. "Apache 2.0" with a space, or proprietary text)
// fails the schema. Anything not confirmed here goes into license.name, which
// accepts free text — always schema-valid, if less precise.
var spdxLicenseIDs = map[string]bool{
	"MIT": true, "Apache-2.0": true, "BSD-2-Clause": true, "BSD-3-Clause": true,
	"ISC": true, "MPL-2.0": true, "LGPL-2.1": true, "LGPL-2.1-only": true,
	"LGPL-3.0": true, "LGPL-3.0-only": true, "GPL-2.0": true, "GPL-2.0-only": true,
	"GPL-3.0": true, "GPL-3.0-only": true, "GPL-3.0-or-later": true,
	"AGPL-3.0": true, "AGPL-3.0-only": true, "Unlicense": true, "0BSD": true,
	"CC0-1.0": true, "CC-BY-4.0": true, "BSL-1.0": true, "Zlib": true,
	"Artistic-2.0": true, "EPL-2.0": true, "WTFPL": true, "Python-2.0": true,
}

// cdxLicenseFor routes a license string to license.id (valid SPDX IDs only) or
// license.name (everything else), keeping the CycloneDX document schema-valid.
func cdxLicenseFor(license string) CDXLicense {
	if spdxLicenseIDs[license] {
		return CDXLicense{ID: license}
	}
	return CDXLicense{Name: license}
}
