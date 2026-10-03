package bench

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const validManifest = `version: 1
projects:
  sdk:
    - path: src/sdk/types/
      provenance:
        kind: generated
        upstream: https://example.invalid/openapi.yml
        basis: every file carries the generator header
    - path: src/sdk/_vendor/lib/
      provenance:
        kind: vendored
        upstream: lib v0.2.0
        basis: file headers name the upstream release
  docs-site:
    - path: docs/v1.0/
      provenance:
        kind: versioned
        source: docs/v2.0/
        basis: docs.json lists v1.0 and v2.0, v2.0 the default
`

// Every field a declaration carries survives loading unchanged: provenance is
// a supplied fact, and a loader that normalised or dropped part of it would be
// rewriting someone else's claim.
func TestCorpusProvenance_SurvivesLoading(t *testing.T) {
	m, err := ParseCorpusProvenance([]byte(validManifest))
	if err != nil {
		t.Fatalf("valid manifest rejected: %v", err)
	}
	want := map[string][]DeclaredSource{
		"sdk": {
			{Path: "src/sdk/types/", Provenance: Provenance{Kind: ProvenanceGenerated,
				Upstream: "https://example.invalid/openapi.yml", Basis: "every file carries the generator header"}},
			{Path: "src/sdk/_vendor/lib/", Provenance: Provenance{Kind: ProvenanceVendored,
				Upstream: "lib v0.2.0", Basis: "file headers name the upstream release"}},
		},
		"docs-site": {
			{Path: "docs/v1.0/", Provenance: Provenance{Kind: ProvenanceVersioned,
				Source: "docs/v2.0/", Basis: "docs.json lists v1.0 and v2.0, v2.0 the default"}},
		},
	}
	if !reflect.DeepEqual(m.Projects, want) {
		t.Errorf("loaded projects =\n%#v\nwant\n%#v", m.Projects, want)
	}
	if got := m.ProjectNames(); strings.Join(got, ",") != "docs-site,sdk" {
		t.Errorf("ProjectNames() = %v, want sorted names", got)
	}
}

func decl(path, body string) string {
	return "version: 1\nprojects:\n  p:\n    - path: " + path + "\n      provenance:\n" + body
}

// Each malformed declaration fails, and the message names what is wrong. The
// substring is the contract: an operator reading only the error must be able to
// fix the manifest.
func TestCorpusProvenance_RejectsMalformedDeclarations(t *testing.T) {
	const basis = "        basis: stated by the project\n"
	cases := []struct {
		name, manifest, want string
	}{
		{"unsupported kind",
			decl("a/", "        kind: translated\n        source: b/\n"+basis),
			`provenance.kind "translated" is not supported; supported kinds: generated, versioned, vendored`},
		{"missing kind",
			decl("a/", "        source: b/\n"+basis),
			`provenance.kind "" is not supported`},
		{"missing basis",
			decl("a/", "        kind: vendored\n        upstream: lib\n"),
			"provenance.basis is required"},
		{"versioned without a source",
			decl("a/", "        kind: versioned\n"+basis),
			"versioned requires provenance.source"},
		{"versioned pointing outside the tree",
			decl("a/", "        kind: versioned\n        source: b/\n        upstream: elsewhere\n"+basis),
			"versioned takes provenance.source, not provenance.upstream"},
		{"vendored without an upstream",
			decl("a/", "        kind: vendored\n"+basis),
			"vendored requires provenance.upstream"},
		{"vendored with an in-tree source",
			decl("a/", "        kind: vendored\n        upstream: lib\n        source: b/\n"+basis),
			"vendored takes provenance.upstream, not provenance.source"},
		{"generated with both origins",
			decl("a/", "        kind: generated\n        upstream: spec\n        source: spec.yml\n"+basis),
			"generated requires exactly one of"},
		{"generated with no origin",
			decl("a/", "        kind: generated\n"+basis),
			"generated requires exactly one of"},
		{"absolute path",
			decl("/etc/", "        kind: vendored\n        upstream: lib\n"+basis),
			`path "/etc/": must be a clean path relative to the project root`},
		{"path escaping the project",
			decl("../other/", "        kind: vendored\n        upstream: lib\n"+basis),
			"must be a clean path relative to the project root"},
		{"unclean path",
			decl("a/./b/", "        kind: vendored\n        upstream: lib\n"+basis),
			"must be a clean path relative to the project root"},
		{"backslash path",
			decl(`'a\b'`, "        kind: vendored\n        upstream: lib\n"+basis),
			"use forward slashes"},
		{"invalid source reference",
			decl("a/", "        kind: versioned\n        source: ../b/\n"+basis),
			`provenance.source "../b/": must be a clean path relative to the project root`},
		{"source is the path itself",
			decl("a/", "        kind: versioned\n        source: a/\n"+basis),
			"overlaps its own path"},
		{"source inside the declared directory",
			decl("a/", "        kind: versioned\n        source: a/b/\n"+basis),
			"overlaps its own path"},
		{"misspelt field",
			decl("a/", "        kind: vendored\n        upstrem: lib\n"+basis),
			"field upstrem not found"},
		{"unsupported version",
			"version: 2\nprojects: {}\n",
			"version 2 is not supported; this build reads version 1"},
		{"missing version",
			"projects: {}\n",
			"version 0 is not supported"},
		{"project name that is a path",
			"version: 1\nprojects:\n  owner/repo: []\n",
			`project "owner/repo": must be a corpus directory name`},
		{"overlapping declarations",
			"version: 1\nprojects:\n  p:\n" +
				"    - path: docs/\n      provenance: {kind: vendored, upstream: x, basis: y}\n" +
				"    - path: docs/v1/\n      provenance: {kind: vendored, upstream: x, basis: y}\n",
			`sources "docs/" and "docs/v1/" overlap`},
		{"duplicate declarations",
			"version: 1\nprojects:\n  p:\n" +
				"    - path: a.py\n      provenance: {kind: vendored, upstream: x, basis: y}\n" +
				"    - path: a.py\n      provenance: {kind: vendored, upstream: x, basis: y}\n",
			`sources "a.py" and "a.py" overlap`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseCorpusProvenance([]byte(tc.manifest))
			if err == nil {
				t.Fatalf("accepted:\n%s", tc.manifest)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q\nwant it to contain %q", err, tc.want)
			}
		})
	}
}

// A manifest with several problems reports all of them, so it is fixed in one
// pass rather than one error per run.
func TestCorpusProvenance_ReportsEveryProblem(t *testing.T) {
	_, err := ParseCorpusProvenance([]byte("version: 1\nprojects:\n  p:\n" +
		"    - path: a/\n      provenance: {kind: mirrored, basis: y}\n" +
		"    - path: b/\n      provenance: {kind: vendored, upstream: x}\n"))
	if err == nil {
		t.Fatal("accepted a manifest with two invalid declarations")
	}
	for _, want := range []string{`sources[0] (a/): provenance.kind "mirrored"`, "sources[1] (b/): provenance.basis is required"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not report %q:\n%v", want, err)
		}
	}
}

func writeTree(t *testing.T, root string, files ...string) {
	t.Helper()
	for _, f := range files {
		p := filepath.Join(root, filepath.FromSlash(f))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// Provenance is a property of a pinned tree. A declaration naming a path the
// tree does not hold -- written for another commit, or misspelt -- fails, and so
// does one declared for a project the corpus does not contain.
func TestCorpusProvenance_CheckedAgainstTheTree(t *testing.T) {
	corpus := t.TempDir()
	writeTree(t, filepath.Join(corpus, "sdk"), "src/sdk/types/a.py", "src/sdk/_vendor/lib/b.py")
	writeTree(t, filepath.Join(corpus, "docs-site"), "docs/v1.0/index.md", "docs/v2.0/index.md")

	m, err := ParseCorpusProvenance([]byte(validManifest))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.CheckCorpus(corpus, []string{"sdk", "docs-site"}); err != nil {
		t.Fatalf("a manifest that matches its tree failed: %v", err)
	}

	cases := []struct {
		name, manifest string
		projects       []string
		want           string
	}{
		{"missing path",
			decl("src/gone/", "        kind: vendored\n        upstream: x\n        basis: y\n"),
			[]string{"p"}, `path "src/gone/" does not exist in the scanned tree`},
		{"missing source",
			decl("docs/v1.0/", "        kind: versioned\n        source: docs/v9/\n        basis: y\n"),
			[]string{"p"}, `provenance.source "docs/v9/" does not exist in the scanned tree`},
		{"directory spelt as a file",
			decl("docs/v1.0", "        kind: versioned\n        source: docs/v2.0/\n        basis: y\n"),
			[]string{"p"}, `path "docs/v1.0" is a directory; spell it "docs/v1.0/"`},
		{"file spelt as a directory",
			decl("docs/v1.0/index.md/", "        kind: versioned\n        source: docs/v2.0/\n        basis: y\n"),
			[]string{"p"}, "is declared as a directory and is a file"},
		{"project not in the corpus",
			decl("docs/v1.0/", "        kind: versioned\n        source: docs/v2.0/\n        basis: y\n"),
			[]string{"docs-site"}, `project "p" is declared but is not in the corpus`},
	}
	writeTree(t, filepath.Join(corpus, "p"), "docs/v1.0/index.md", "docs/v2.0/index.md")
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, err := ParseCorpusProvenance([]byte(tc.manifest))
			if err != nil {
				t.Fatalf("structurally invalid fixture: %v", err)
			}
			err = m.CheckCorpus(corpus, tc.projects)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v\nwant it to contain %q", err, tc.want)
			}
		})
	}
}

// The manifests shipped in this repository parse. Their tree check needs the
// pinned clones and runs when the bench does; this guards the structure.
func TestShippedCorpusProvenanceManifestsParse(t *testing.T) {
	for _, f := range []string{
		"../../docs/benchmarks/corpus-provenance.yaml",
		"../../docs/benchmarks/2026-09-15/provenance.yaml",
	} {
		m, err := LoadCorpusProvenance(f)
		if err != nil {
			t.Errorf("%s: %v", f, err)
			continue
		}
		if len(m.Projects) == 0 {
			t.Errorf("%s declares nothing", f)
		}
	}
}
