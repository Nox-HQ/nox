package slop

import "testing"

func TestEcosystemForExt(t *testing.T) {
	cases := map[string]ecosystem{
		".py": ecoPyPI, ".pyi": ecoPyPI,
		".js": ecoNPM, ".jsx": ecoNPM, ".mjs": ecoNPM, ".cjs": ecoNPM,
		".ts": ecoNPM, ".tsx": ecoNPM, ".mts": ecoNPM, ".cts": ecoNPM,
		".go": "", ".txt": "", "": "",
	}
	for ext, want := range cases {
		if got := ecosystemForExt(ext); got != want {
			t.Errorf("ecosystemForExt(%q) = %q, want %q", ext, got, want)
		}
	}
}

func TestExtractPythonImports(t *testing.T) {
	src := []byte(`import os
import numpy as np, pandas
from . import sibling
from .utils import helper
from flask import Flask
import a.b.c  # trailing comment
from requests.sessions import Session
`)
	got := extractImports(ecoPyPI, src)
	specs := make(map[string]bool)
	for _, r := range got {
		specs[r.spec] = true
	}
	for _, want := range []string{"os", "numpy", "pandas", ".", ".utils", "flask", "a.b.c", "requests.sessions"} {
		if !specs[want] {
			t.Errorf("missing python import spec %q; got %v", want, specs)
		}
	}
}

func TestExtractJSImports(t *testing.T) {
	src := []byte(`import express from 'express';
import { readFile } from "node:fs";
import './local.js';
const lodash = require('lodash/fp');
const x = await import("@scope/pkg/sub");
`)
	got := extractImports(ecoNPM, src)
	specs := make(map[string]bool)
	for _, r := range got {
		specs[r.spec] = true
	}
	for _, want := range []string{"express", "node:fs", "./local.js", "lodash/fp", "@scope/pkg/sub"} {
		if !specs[want] {
			t.Errorf("missing js import spec %q; got %v", want, specs)
		}
	}
}

func TestPackageNamePyPI(t *testing.T) {
	cases := []struct {
		spec   string
		want   string
		wantOK bool
	}{
		{"os", "os", true},
		{"a.b.c", "a", true},
		{"requests.sessions", "requests", true},
		{".", "", false},
		{".utils", "", false},
		{"", "", false},
	}
	for _, c := range cases {
		got, ok := packageName(ecoPyPI, c.spec)
		if got != c.want || ok != c.wantOK {
			t.Errorf("packageName(pypi, %q) = (%q,%v), want (%q,%v)", c.spec, got, ok, c.want, c.wantOK)
		}
	}
}

func TestPackageNameNPM(t *testing.T) {
	cases := []struct {
		spec   string
		want   string
		wantOK bool
	}{
		{"express", "express", true},
		{"lodash/fp", "lodash", true},
		{"@scope/pkg/sub", "@scope/pkg", true},
		{"@scope/pkg", "@scope/pkg", true},
		{"node:fs", "fs", true},
		{"./local", "", false},
		{"/abs", "", false},
		{"", "", false},
	}
	for _, c := range cases {
		got, ok := packageName(ecoNPM, c.spec)
		if got != c.want || ok != c.wantOK {
			t.Errorf("packageName(npm, %q) = (%q,%v), want (%q,%v)", c.spec, got, ok, c.want, c.wantOK)
		}
	}
}

func TestIsStdlib(t *testing.T) {
	if !isStdlib(ecoPyPI, "os") || !isStdlib(ecoPyPI, "asyncio") {
		t.Error("expected python stdlib membership for os/asyncio")
	}
	if isStdlib(ecoPyPI, "flask") {
		t.Error("flask is not python stdlib")
	}
	if !isStdlib(ecoNPM, "fs") || !isStdlib(ecoNPM, "path") {
		t.Error("expected node builtin membership for fs/path")
	}
	if isStdlib(ecoNPM, "express") {
		t.Error("express is not a node builtin")
	}
}

// A generated import statement is not an import.
//
// vercel/ai writes source files from template literals, and the generated text
// contains an ordinary quoted specifier:
//
//	await import('${moduleName}');
//	import transformer from '${toRelativeImportPath(paths.test, paths.codemod)}';
//
// The extractor matches quoted specifiers, which is right for a real import and
// also right for the quoted specifier inside the generated text — it cannot
// tell the two apart from the quote alone. What tells them apart is the name:
// no registry can serve a package containing `$`, `{` or `}`. SLOP-001 reports
// "this import resolves to no declared dependency" as evidence of a
// hallucinated package, and that inference needs a package name to start from.
func TestGeneratedImportSpecifierIsNotAPackage(t *testing.T) {
	for _, spec := range []string{
		"${moduleName}",
		"@ai-sdk/${pkgName}",
		"${toRelativeImportPath(paths.test, paths.codemod)}",
		"@${scope}/thing",
		"pkg name with spaces",
	} {
		if name, ok := packageName(ecoNPM, spec); ok {
			t.Errorf("packageName(npm, %q) = %q, true — no registry can serve that "+
				"name, so reporting it as an undeclared dependency asserts a "+
				"hallucinated package on the strength of a code generator", spec, name)
		}
	}
}

// The control. Every shape above is rejected for containing a character npm
// forbids, so the check has to keep accepting the names that do not — including
// the awkward legacy ones, where a false negative is silent.
func TestRealPackageNamesStillResolve(t *testing.T) {
	for spec, want := range map[string]string{
		"react":                           "react",
		"@ai-sdk/openai":                  "@ai-sdk/openai",
		"@ai-sdk/openai/internal":         "@ai-sdk/openai",
		"lodash.debounce":                 "lodash.debounce",
		"node-fetch":                      "node-fetch",
		"JSONStream":                      "JSONStream",
		"@babel/plugin-transform-runtime": "@babel/plugin-transform-runtime",
		"zod/v4":                          "zod",
	} {
		got, ok := packageName(ecoNPM, spec)
		if !ok || got != want {
			t.Errorf("packageName(npm, %q) = %q, %v — want %q, true", spec, got, ok, want)
		}
	}
}
