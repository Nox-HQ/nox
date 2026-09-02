package depimports

import "testing"

// The ordinary import idiom of each covered ecosystem must name its
// distribution. These are the shapes real code is written in, not the one shape
// that happens to work — the same measure that exposed the taint engine's
// import gap.
func TestOrdinaryIdiomsNameTheDistribution(t *testing.T) {
	cases := []struct {
		name, file, src, eco, pkg string
		want                      bool
	}{
		{"npm require", "a.js", `const _ = require("lodash");`, "npm", "lodash", true},
		{"npm subpath", "a.js", `const fp = require("lodash/fp");`, "npm", "lodash", true},
		{"npm esm from", "a.ts", `import { z } from "zod";`, "npm", "zod", true},
		{"npm bare import", "a.js", `import "core-js";`, "npm", "core-js", true},
		{"npm scoped", "a.ts", `import x from "@babel/core";`, "npm", "@babel/core", true},
		{"npm node: prefix names the builtin, not the fs package", "a.js", `import fs from "node:fs";`, "npm", "fs", false},
		{"npm relative names nothing", "a.js", `const x = require("./util");`, "npm", "util", false},
		{"pypi import", "a.py", "import requests\n", "PyPI", "requests", true},
		{"pypi from", "a.py", "from requests.adapters import x\n", "PyPI", "requests", true},
		{"pypi dash normalises", "a.py", "import ruamel_yaml\n", "PyPI", "ruamel-yaml", true},
		{"cargo use", "a.rs", "use serde_json::Value;\n", "cargo", "serde-json", true},
		{"cargo extern", "a.rs", "extern crate rand;\n", "crates.io", "rand", true},
		{"cargo crate:: is local", "a.rs", "use crate::thing;\n", "cargo", "crate", false},
		{"pub package uri", "a.dart", `import 'package:http/http.dart';`, "pub", "http", true},
		{"rubygems require", "a.rb", `require "nokogiri"`, "rubygems", "nokogiri", true},
		{"rubygems subpath", "a.rb", `require "active_support/core_ext"`, "gem", "active_support", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ix := New()
			ix.Add(c.file, []byte(c.src))
			if got := ix.Imports(c.eco, c.pkg); got != c.want {
				t.Errorf("Imports(%q, %q) = %v, want %v", c.eco, c.pkg, got, c.want)
			}
		})
	}
}

// The distinction the whole package rests on: an empty set because nothing
// imported the package, versus an empty set because there is no source of that
// language here. Only the first is evidence, and neither may refute.
func TestUnseenLanguageIsNotAnAbsence(t *testing.T) {
	ix := New()
	ix.Add("a.py", []byte("import requests\n"))

	if !ix.Known("PyPI") {
		t.Error("a Python file was read; PyPI must be Known")
	}
	if ix.Known("npm") {
		t.Error("no JavaScript was read, so npm must NOT be Known")
	}
	if ix.Imports("npm", "lodash") {
		t.Error("nothing may be reported as imported from a language never read")
	}
}

// A file with no imports still makes its ecosystem Known: that is precisely the
// case where "not imported" is a real observation rather than a blind spot.
func TestFileWithoutImportsStillMakesEcosystemKnown(t *testing.T) {
	ix := New()
	ix.Add("a.py", []byte("x = 1\n"))
	if !ix.Known("pypi") {
		t.Error("the file was read; the ecosystem is Known even with no imports")
	}
	if ix.Imports("pypi", "requests") {
		t.Error("no import must not report as imported")
	}
}

// Ecosystems whose import names a namespace the manifest does not carry are
// declared unsupported rather than guessed at.
func TestUnsupportedEcosystemsSaySo(t *testing.T) {
	for _, e := range []string{"npm", "PyPI", "cargo", "pub", "rubygems"} {
		if !Supported(e) {
			t.Errorf("%s should be supported", e)
		}
	}
	for _, e := range []string{"maven", "nuget", "packagist", "hex", "go"} {
		if Supported(e) {
			t.Errorf("%s must not claim support: its import names a namespace, not the distribution", e)
		}
	}
}
