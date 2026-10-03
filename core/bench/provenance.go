package bench

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Corpus provenance is a SUPPLIED FACT about where part of a scanned tree came
// from: "src/openai/types/ is generated", "docs/v1.10.0/ is a released version of
// the doc set whose canonical copy is docs/v1.15.21/". It is declared by whoever
// assembles a corpus, from what the project itself states, and nothing computes
// one.
//
// That is the whole design, and the reason is measured rather than argued.
// docs/research/evidence-independence/RESULT.md tried to INFER which findings
// share an origin and could not: four reasonable collapse models disagreed by up
// to 9x, a finding's location turned out not to be its evidence (VULN-002 sits on
// a lockfile header, so three repositories' lockfiles hashed as one), and the
// research's own declared "generator family" was wrong -- the two SDKs it called
// one Stainless family were Stainless and Castiron at the commits it scanned.
// Even a careful human inference was a guess.
//
// So a declaration is parsed, validated, kept and shown, and it does NOTHING
// else. It does not touch findings, counts, prevalence, rule-review, calibration
// or any gate; TestCorpusProvenanceHasOneReader keeps it that way. An
// independence estimate built on top of declarations would be an interpretation,
// and it belongs in a separate layer only once enough has been declared to
// measure whether it is any use.
//
// Every declaration names its BASIS -- where the project says so. That field is
// the line between a declaration and an inference: "the directory is called
// _vendor" is not a basis, the file header "Vendored from httpx-aiohttp v0.2.0"
// is.

// ProvenanceKind is what a declared path is relative to its origin.
//
// The list is closed and short on purpose: a kind exists only once a real corpus
// needed it, each one below was found in a pinned corpus tree, and adding one is
// adding a claim nox makes about the world. `translated` and `mirrored` were
// considered and are absent -- crewAI's docs.json declares four languages but no
// source language, so a translation's origin is exactly the kind of thing that
// would have to be guessed.
type ProvenanceKind string

const (
	// ProvenanceGenerated is output produced by a tool from a specification. Found in
	// openai-python and anthropic-sdk-python, where every file under
	// src/<pkg>/resources/ and src/<pkg>/types/ carries "File generated from our
	// OpenAPI spec by Stainless".
	ProvenanceGenerated ProvenanceKind = "generated"
	// ProvenanceVersioned is another released version of a document set whose
	// canonical copy is in the same tree. Found in crewAI, whose docs/docs.json
	// declares 39 versions matching its 39 docs/<version>/ directories.
	ProvenanceVersioned ProvenanceKind = "versioned"
	// ProvenanceVendored is third-party code copied in from an upstream project.
	// Found in anthropic-sdk-python, whose src/anthropic/_vendor/httpx_aiohttp/
	// files state "Vendored from httpx-aiohttp v0.2.0 ... verbatim".
	ProvenanceVendored ProvenanceKind = "vendored"
)

var provenanceKinds = []ProvenanceKind{ProvenanceGenerated, ProvenanceVersioned, ProvenanceVendored}

// CorpusProvenanceVersion is the only manifest schema version this build reads.
const CorpusProvenanceVersion = 1

// Provenance is one declared origin.
//
// Source is a path in the SAME project tree; Upstream names something outside
// it. They are separate fields rather than one `source` string because the two
// are validated differently -- a tree path must exist in the tree it describes,
// an upstream cannot be checked from here -- and a single field would have to
// guess which one it was given.
type Provenance struct {
	Kind     ProvenanceKind `yaml:"kind" json:"kind"`
	Source   string         `yaml:"source,omitempty" json:"source,omitempty"`
	Upstream string         `yaml:"upstream,omitempty" json:"upstream,omitempty"`
	Basis    string         `yaml:"basis" json:"basis"`
}

// DeclaredSource binds a path in a project to its declared provenance. A path
// ending in "/" is a directory and claims every file under it, so it must be
// true for every one of them.
type DeclaredSource struct {
	Path       string     `yaml:"path" json:"path"`
	Provenance Provenance `yaml:"provenance" json:"provenance"`
}

// CorpusProvenance is a manifest: declarations per corpus project, keyed by the
// project's directory name in the corpus (e.g. `openai--openai-python` for
// --autocorpus).
type CorpusProvenance struct {
	Version  int                         `yaml:"version"`
	Projects map[string][]DeclaredSource `yaml:"projects"`
}

// ParseCorpusProvenance reads a manifest and validates its structure. Every
// problem is reported, not just the first, so a manifest is fixed in one pass.
//
// Unknown fields are errors: a misspelt `upstrem:` silently dropped would leave a
// declaration that reads as complete and is not.
func ParseCorpusProvenance(data []byte) (CorpusProvenance, error) {
	var m CorpusProvenance
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&m); err != nil {
		return CorpusProvenance{}, fmt.Errorf("corpus provenance: %w", err)
	}
	if err := m.validate(); err != nil {
		return CorpusProvenance{}, err
	}
	return m, nil
}

// LoadCorpusProvenance reads and validates a manifest file.
func LoadCorpusProvenance(file string) (CorpusProvenance, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return CorpusProvenance{}, fmt.Errorf("corpus provenance: %w", err)
	}
	m, err := ParseCorpusProvenance(data)
	if err != nil {
		return CorpusProvenance{}, fmt.Errorf("%s: %w", file, err)
	}
	return m, nil
}

func (m CorpusProvenance) validate() error {
	var errs []error
	if m.Version != CorpusProvenanceVersion {
		errs = append(errs, fmt.Errorf("version %d is not supported; this build reads version %d",
			m.Version, CorpusProvenanceVersion))
	}
	for _, project := range m.ProjectNames() {
		if strings.TrimSpace(project) == "" || strings.ContainsAny(project, `/\`) {
			errs = append(errs, fmt.Errorf("project %q: must be a corpus directory name", project))
			continue
		}
		errs = append(errs, validateProject(project, m.Projects[project])...)
	}
	return errors.Join(errs...)
}

func validateProject(project string, decls []DeclaredSource) []error {
	var errs []error
	for i, d := range decls {
		where := fmt.Sprintf("project %q, sources[%d] (%s)", project, i, d.Path)
		for _, err := range validateDeclaration(d) {
			errs = append(errs, fmt.Errorf("%s: %w", where, err))
		}
	}
	// Overlap is ambiguous rather than additive: a file under two declared
	// paths would have two origins, and picking one is the inference this
	// vocabulary exists to avoid.
	for i := range decls {
		for j := i + 1; j < len(decls); j++ {
			a, b := decls[i].Path, decls[j].Path
			if a == b || covers(a, b) || covers(b, a) {
				errs = append(errs, fmt.Errorf("project %q: sources %q and %q overlap; a path may be declared once",
					project, a, b))
			}
		}
	}
	return errs
}

func validateDeclaration(d DeclaredSource) []error {
	var errs []error
	if err := checkTreePath("path", d.Path); err != nil {
		errs = append(errs, err)
	}
	p := d.Provenance
	if strings.TrimSpace(p.Basis) == "" {
		errs = append(errs, errors.New("provenance.basis is required: name where the project itself declares this, "+
			"or it is an inference, not a declaration"))
	}
	if p.Source != "" {
		if err := checkTreePath("provenance.source", p.Source); err != nil {
			errs = append(errs, err)
		} else if p.Source == d.Path || covers(p.Source, d.Path) || covers(d.Path, p.Source) {
			errs = append(errs, fmt.Errorf("provenance.source %q overlaps its own path; a copy cannot be its own origin", p.Source))
		}
	}
	switch p.Kind {
	case ProvenanceVersioned:
		if p.Source == "" {
			errs = append(errs, errors.New("versioned requires provenance.source: the canonical copy in this tree"))
		}
		if p.Upstream != "" {
			errs = append(errs, errors.New("versioned takes provenance.source, not provenance.upstream"))
		}
	case ProvenanceVendored:
		if p.Upstream == "" {
			errs = append(errs, errors.New("vendored requires provenance.upstream: the project it was copied from"))
		}
		if p.Source != "" {
			errs = append(errs, errors.New("vendored takes provenance.upstream, not provenance.source"))
		}
	case ProvenanceGenerated:
		if (p.Source == "") == (p.Upstream == "") {
			errs = append(errs, errors.New("generated requires exactly one of provenance.source (an in-tree "+
				"specification) or provenance.upstream (an external one)"))
		}
	default:
		errs = append(errs, fmt.Errorf("provenance.kind %q is not supported; supported kinds: %s",
			p.Kind, joinKinds()))
	}
	return errs
}

// checkTreePath accepts a clean, relative, forward-slash path inside the project.
// A trailing "/" marks a directory and is kept.
func checkTreePath(field, p string) error {
	if strings.TrimSpace(p) == "" {
		return fmt.Errorf("%s is required", field)
	}
	if strings.Contains(p, `\`) {
		return fmt.Errorf("%s %q: use forward slashes", field, p)
	}
	trimmed := strings.TrimSuffix(p, "/")
	if path.IsAbs(p) || filepath.IsAbs(p) || trimmed == "" || path.Clean(trimmed) != trimmed ||
		trimmed == ".." || strings.HasPrefix(trimmed, "../") || trimmed == "." {
		return fmt.Errorf("%s %q: must be a clean path relative to the project root", field, p)
	}
	return nil
}

// covers reports whether directory declaration dir contains p.
func covers(dir, p string) bool {
	return strings.HasSuffix(dir, "/") && strings.HasPrefix(p, dir)
}

func joinKinds() string {
	names := make([]string, len(provenanceKinds))
	for i, k := range provenanceKinds {
		names[i] = string(k)
	}
	return strings.Join(names, ", ")
}

// ProjectNames returns the declared projects in a stable order.
func (m CorpusProvenance) ProjectNames() []string {
	names := make([]string, 0, len(m.Projects))
	for name := range m.Projects {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// CheckCorpus validates the manifest against the corpus it describes. A
// declaration for a project the corpus does not hold is an error, not a no-op:
// a typo in a project name would otherwise drop every declaration under it and
// the report would read as if none had been made.
func (m CorpusProvenance) CheckCorpus(corpusDir string, projects []string) error {
	present := make(map[string]bool, len(projects))
	for _, p := range projects {
		present[p] = true
	}
	var errs []error
	for _, name := range m.ProjectNames() {
		if !present[name] {
			errs = append(errs, fmt.Errorf("project %q is declared but is not in the corpus", name))
			continue
		}
		errs = append(errs, checkTree(name, filepath.Join(corpusDir, name), m.Projects[name])...)
	}
	return errors.Join(errs...)
}

// checkTree confirms every declared path and in-tree source exists, with the
// kind of entry (file or directory) its spelling claims. Provenance is a property
// of a pinned tree, not of a project: at their autocorpus refs both SDKs are
// Stainless-generated, at later commits one is not, so a manifest written for one
// pin must fail loudly against another.
func checkTree(project, root string, decls []DeclaredSource) []error {
	var errs []error
	for i, d := range decls {
		for _, ref := range []struct{ field, p string }{{"path", d.Path}, {"provenance.source", d.Provenance.Source}} {
			if ref.p == "" {
				continue
			}
			info, err := os.Stat(filepath.Join(root, filepath.FromSlash(strings.TrimSuffix(ref.p, "/"))))
			switch {
			case err != nil:
				errs = append(errs, fmt.Errorf("project %q, sources[%d]: %s %q does not exist in the scanned tree",
					project, i, ref.field, ref.p))
			case strings.HasSuffix(ref.p, "/") && !info.IsDir():
				errs = append(errs, fmt.Errorf("project %q, sources[%d]: %s %q is declared as a directory and is a file",
					project, i, ref.field, ref.p))
			case !strings.HasSuffix(ref.p, "/") && info.IsDir():
				errs = append(errs, fmt.Errorf("project %q, sources[%d]: %s %q is a directory; spell it %q",
					project, i, ref.field, ref.p, ref.p+"/"))
			}
		}
	}
	return errs
}
