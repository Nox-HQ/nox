package deps

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nox-hq/nox/core/applicability"
)

// tree writes files and returns a sourceImports over them.
func tree(t *testing.T, files map[string]string) *sourceImports {
	t.Helper()
	dir := t.TempDir()
	s := &sourceImports{}
	for name, body := range files {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		s.paths = append(s.paths, p)
	}
	return s
}

// The gap this closes: applicability was implemented for Go alone, so every
// npm, PyPI, Cargo, pub and RubyGems finding reported the same "unexamined"
// verdict however plainly the project used the package.
func TestApplicabilityClimbsForNonGoEcosystems(t *testing.T) {
	cases := []struct {
		name, eco, pkg, file, src string
	}{
		{"npm", "npm", "lodash", "a.js", `const _ = require("lodash");`},
		{"pypi", "PyPI", "requests", "a.py", "import requests\n"},
		{"cargo", "crates.io", "serde-json", "a.rs", "use serde_json::Value;\n"},
		{"pub", "pub", "http", "a.dart", `import 'package:http/http.dart';`},
		{"rubygems", "rubygems", "nokogiri", "a.rb", `require "nokogiri"`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src := tree(t, map[string]string{c.file: c.src})
			v := applicabilityFor(Package{Name: c.pkg, Ecosystem: c.eco},
				goAdvisory(c.pkg), nil, false, src)

			if v.Reached != applicability.SymbolUsed {
				t.Errorf("reached %q, want %q — the project imports the package by name",
					v.Reached, applicability.SymbolUsed)
			}
			// Climbing must never turn into a refutation.
			if v.Outcome == applicability.NotImpacting {
				t.Error("a direct import must never produce NotImpacting")
			}
		})
	}
}

// The property the whole design rests on: a package the source does not import
// is NOT refuted. goImportedPackages uses the toolchain precisely because a
// vulnerable package is usually reached THROUGH a dependency, which parsing the
// repository's own imports cannot see. So absence here is not evidence.
func TestNotImportedIsNeverARefutation(t *testing.T) {
	src := tree(t, map[string]string{"a.js": `const x = require("express");`})
	v := applicabilityFor(Package{Name: "lodash", Ecosystem: "npm"},
		goAdvisory("lodash"), nil, false, src)

	if v.Outcome == applicability.NotImpacting {
		t.Fatal("a package absent from the source may be reached through a dependency; refuting it would hide a real vulnerability")
	}
	if v.Reached != applicability.AffectedVersion {
		t.Errorf("reached %q, want %q — nothing above was established", v.Reached, applicability.AffectedVersion)
	}
}

// An ecosystem whose import names a namespace rather than the distribution is
// left alone rather than guessed at.
func TestUnsupportedEcosystemIsUnchanged(t *testing.T) {
	src := tree(t, map[string]string{"A.java": "import com.fasterxml.jackson.databind.ObjectMapper;\n"})
	v := applicabilityFor(Package{Name: "jackson-databind", Ecosystem: "maven"},
		goAdvisory("jackson-databind"), nil, false, src)

	if v.Reached != applicability.AffectedVersion {
		t.Errorf("reached %q, want %q", v.Reached, applicability.AffectedVersion)
	}
}

// Nothing is read until a finding asks: the index costs a read of every source
// file, and most scans have no dependency finding this can answer for.
func TestSourceIsNotReadUntilAsked(t *testing.T) {
	src := tree(t, map[string]string{"a.js": `require("lodash")`})
	if src.index != nil {
		t.Fatal("index built before any finding asked")
	}
	_ = applicabilityFor(Package{Name: "lodash", Ecosystem: "npm"}, goAdvisory("lodash"), nil, false, src)
	if src.index == nil {
		t.Error("index should have been built on first use")
	}
}
