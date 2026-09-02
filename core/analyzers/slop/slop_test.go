package slop

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/nox-hq/nox/core/discovery"
)

// writeTree writes files under a temp dir and returns discovery.Artifacts for
// each, classified by extension/name so ScanArtifacts can read them from disk.
func writeTree(t *testing.T, files map[string]string) []discovery.Artifact {
	t.Helper()
	root := t.TempDir()
	var arts []discovery.Artifact
	for rel, content := range files {
		abs := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(abs, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		typ := discovery.Unknown
		switch ext := filepath.Ext(rel); {
		case ecosystemForExt(ext) != "":
			typ = discovery.Source
		case isManifest(filepath.Base(rel)):
			typ = discovery.Lockfile
		}
		arts = append(arts, discovery.Artifact{Path: rel, AbsPath: abs, Type: typ})
	}
	return arts
}

func findingsFor(t *testing.T, files map[string]string) []string {
	t.Helper()
	arts := writeTree(t, files)
	fs, err := NewAnalyzer().ScanArtifacts(context.Background(), arts)
	if err != nil {
		t.Fatal(err)
	}
	var pkgs []string
	items := fs.Findings()
	for i := range items {
		if items[i].RuleID == "SLOP-001" {
			pkgs = append(pkgs, items[i].Metadata["package"])
		}
	}
	return pkgs
}

func hasPkg(pkgs []string, name string) bool {
	for _, p := range pkgs {
		if p == name {
			return true
		}
	}
	return false
}

func TestScanFlagsHallucinatedPython(t *testing.T) {
	pkgs := findingsFor(t, map[string]string{
		"requirements.txt": "flask>=2.0\nrequests\n",
		"app.py": `import os
import flask
import requests
import smart_config_parser_ai
from . import helpers
`,
	})
	if !hasPkg(pkgs, "smart_config_parser_ai") {
		t.Errorf("expected hallucinated package flagged; got %v", pkgs)
	}
	for _, real := range []string{"os", "flask", "requests"} {
		if hasPkg(pkgs, real) {
			t.Errorf("false positive: %q flagged; got %v", real, pkgs)
		}
	}
}

func TestScanFlagsHallucinatedNPM(t *testing.T) {
	pkgs := findingsFor(t, map[string]string{
		"package.json": `{"dependencies":{"express":"^4"},"devDependencies":{"@types/node":"20"}}`,
		"server.ts": `import express from 'express';
import { readFile } from 'node:fs';
import { magicAuth } from 'ultra-secure-auth-helper';
import './local';
`,
	})
	if !hasPkg(pkgs, "ultra-secure-auth-helper") {
		t.Errorf("expected hallucinated npm package flagged; got %v", pkgs)
	}
	for _, real := range []string{"express", "fs"} {
		if hasPkg(pkgs, real) {
			t.Errorf("false positive: %q flagged; got %v", real, pkgs)
		}
	}
}

func TestScanNoFalsePositiveOnLocalModule(t *testing.T) {
	// A first-party package imported across files must not be flagged.
	pkgs := findingsFor(t, map[string]string{
		"myapp/__init__.py": "",
		"myapp/core.py":     "from myapp import config\nimport myapp.utils\n",
		"myapp/config.py":   "value = 1\n",
	})
	if hasPkg(pkgs, "myapp") {
		t.Errorf("first-party module myapp should not be flagged; got %v", pkgs)
	}
}

func TestScanImportDistMismatchNotFlagged(t *testing.T) {
	pkgs := findingsFor(t, map[string]string{
		"requirements.txt": "pyyaml\nopencv-python\n",
		"m.py":             "import yaml\nimport cv2\n",
	})
	if hasPkg(pkgs, "yaml") || hasPkg(pkgs, "cv2") {
		t.Errorf("import/dist-name mismatch should not be flagged; got %v", pkgs)
	}
}

func TestScanDeduplicatesPerFile(t *testing.T) {
	arts := writeTree(t, map[string]string{
		"a.py": "import ghostpkg\nimport ghostpkg\nfrom ghostpkg import x\n",
	})
	fs, err := NewAnalyzer().ScanArtifacts(context.Background(), arts)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, f := range fs.Findings() {
		if f.Metadata["package"] == "ghostpkg" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected ghostpkg flagged once per file, got %d", count)
	}
}

func TestScanPrivateAndLegacyPythonModulesNotFlagged(t *testing.T) {
	// Underscore-led modules cannot be registry packages (PEP 508 names start
	// with a letter or digit); Python 2 names live in compatibility shims.
	pkgs := findingsFor(t, map[string]string{
		"m.py": "from _typeshed import StrPath\nimport _ssl\nfrom _pytest.fixtures import fixture\n" +
			"try:\n    import queue\nexcept ImportError:\n    import Queue\n" +
			"import distutils.util\nfrom compression import zstd\nimport urllib2\n",
	})
	if len(pkgs) != 0 {
		t.Errorf("private and legacy stdlib names must not be flagged; got %v", pkgs)
	}
}

func TestScanMonorepoSrcLayoutIsLocal(t *testing.T) {
	// certbot-ci/src/certbot_integration_tests is first-party even though the
	// src segment is not at the tree root; myapp/plugins is a subpackage, so a
	// bare `import plugins` remains external.
	pkgs := findingsFor(t, map[string]string{
		"certbot-ci/src/certbot_integration_tests/__init__.py": "",
		"certbot-ci/src/certbot_integration_tests/utils/x.py":  "import certbot_integration_tests.conftest\n",
		"tools/pkg/myapp/__init__.py":                          "",
		"tools/pkg/myapp/plugins/__init__.py":                  "",
		"tools/pkg/myapp/plugins/a.py":                         "import myapp.plugins\nimport plugins\n",
	})
	if hasPkg(pkgs, "certbot_integration_tests") || hasPkg(pkgs, "myapp") {
		t.Errorf("first-party packages flagged: %v", pkgs)
	}
	if !hasPkg(pkgs, "plugins") {
		t.Errorf("a nested subpackage name must not vouch for a bare import; got %v", pkgs)
	}
}

func TestScanSkipsVendoredCode(t *testing.T) {
	// Imports inside a vendored library are the library's, resolved against a
	// manifest that is not in this tree. The project's own file still counts.
	pkgs := findingsFor(t, map[string]string{
		"pipenv/vendor/rich/live.py":            "import ipywidgets\n",
		"pipenv/patched/pip/_vendor/socks.py":   "import socks\n",
		"web/static/node_modules/left-pad/i.js": "const x = require('phantom-left-pad');\n",
		"pipenv/help.py":                        "import totally_made_up_pkg\n",
	})
	for _, p := range []string{"ipywidgets", "socks", "phantom-left-pad"} {
		if hasPkg(pkgs, p) {
			t.Errorf("vendored import %q flagged; got %v", p, pkgs)
		}
	}
	if !hasPkg(pkgs, "totally_made_up_pkg") {
		t.Errorf("project import must still be flagged; got %v", pkgs)
	}
}
