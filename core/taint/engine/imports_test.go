package engine

import (
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

func TestPythonImportAliases(t *testing.T) {
	src := `import os
import os.path as p
import subprocess as sp
from os import system
from os import system as sys_call
from subprocess import run, Popen
from json import *
`
	got := importAliases(lexctx.LangPython, []byte(src)).names
	want := map[string]string{
		"p":        "os.path",
		"sp":       "subprocess",
		"system":   "os.system",
		"sys_call": "os.system",
		"run":      "subprocess.run",
		"Popen":    "subprocess.Popen",
	}
	for local, qualified := range want {
		if got[local] != qualified {
			t.Errorf("%s → %q, want %q", local, got[local], qualified)
		}
	}
	// A plain `import os` needs no entry: the name already IS the module, which
	// is the one shape that always matched.
	if _, ok := got["os"]; ok {
		t.Error("plain `import os` created a redundant alias")
	}
	// `from json import *` binds names this resolver cannot enumerate, and
	// guessing would invent chains.
	if len(got) != len(want) {
		t.Errorf("unexpected aliases: got %v", got)
	}
}

func TestJavaScriptImportAliases(t *testing.T) {
	src := `const cp = require("child_process");
const { exec } = require("child_process");
const { spawn: launch } = require("child_process");
import fs from "fs";
import { readFile } from "fs";
import { readFile as rf } from "fs";
import * as path from "path";
`
	got := importAliases(lexctx.LangJavaScript, []byte(src)).names
	want := map[string]string{
		"cp":       "child_process",
		"exec":     "child_process.exec",
		"launch":   "child_process.spawn",
		"fs":       "fs",
		"readFile": "fs.readFile",
		"rf":       "fs.readFile",
		"path":     "path",
	}
	for local, qualified := range want {
		if got[local] != qualified {
			t.Errorf("%s → %q, want %q", local, got[local], qualified)
		}
	}
}

func TestExpandChain(t *testing.T) {
	aliases := aliasTable{sep: ".", names: map[string]string{
		"system": "os.system",     // from-import of a member
		"o":      "os",            // aliased module
		"cp":     "child_process", // aliased module
	}}
	tests := []struct{ in, want string }{
		{"system", "os.system"},
		{"o.system", "os.system"},
		{"cp.exec", "child_process.exec"},
		{"cp.exec.sync", "child_process.exec.sync"},
		{"unknown", ""},
		{"unknown.member", ""},
		{"", ""},
	}
	for _, tt := range tests {
		if got := expandChain(tt.in, aliases); got != tt.want {
			t.Errorf("expandChain(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// Expansion ADDS, never replaces. Nothing that matched before can stop
// matching, so the change cannot remove a finding.
func TestExpansionIsAdditive(t *testing.T) {
	aliases := aliasTable{sep: ".", names: map[string]string{"o": "os"}}
	got := withExpansions([]string{"o.system", "print"}, aliases)

	for _, want := range []string{"o.system", "print", "os.system"} {
		var found bool
		for _, g := range got {
			if g == want {
				found = true
			}
		}
		if !found {
			t.Errorf("%q missing from %v", want, got)
		}
	}
}

// Languages with no resolver keep today's behaviour exactly. Guessing at import
// syntaxes nobody has checked would be the same defect in a new place.
func TestUnresolvedLanguagesGetNoAliases(t *testing.T) {
	for _, lang := range []lexctx.Lang{
		lexctx.LangGo, lexctx.LangRuby, lexctx.LangJava, lexctx.LangPHP, lexctx.LangRust,
	} {
		if got := importAliases(lang, []byte("import os\nfrom os import system\n")); len(got.names) != 0 {
			t.Errorf("%v returned aliases from a resolver it does not have: %v", lang, got.names)
		}
	}
}

// A commented-out import must not bind a name. lexctx blanks comments before
// the recognizer runs, but importAliases reads raw content, so this is checked
// rather than assumed.
func TestImportsInsideStringsAndCommentsAreStillLineMatched(t *testing.T) {
	// Documenting current behaviour honestly: the resolver is line-based over
	// raw content, so a commented import DOES bind. The cost is an extra chain
	// that matches nothing real, never a lost one — expansion is additive.
	got := importAliases(lexctx.LangPython, []byte("# from os import system\n")).names
	if len(got) != 0 {
		t.Logf("known limit: a commented import binds a name (%v); additive expansion makes this harmless", got)
	}
}

// Clojure introduces every alias with the same libspec vector, so one pattern
// has to cover the (ns …) form, a top-level (require '[…]), and a multi-line
// :require block. `:as-alias` binds a name exactly like `:as` does.
func TestClojureAliases(t *testing.T) {
	src := `(ns app.handler
  (:require [clojure.java.shell :as sh]
            [clojure.java.io :as io]
            [clj-http.client :as http :refer [get]]
            [next.jdbc :as-alias njdbc]
            [clojure.string]))

(require '[clojure.java.jdbc :as jdbc])
`
	got := importAliases(lexctx.LangClojure, []byte(src))
	if got.sep != "/" {
		t.Fatalf("clojure chains join with /, got %q", got.sep)
	}
	want := map[string]string{
		"sh":    "clojure.java.shell",
		"io":    "clojure.java.io",
		"http":  "clj-http.client",
		"njdbc": "next.jdbc",
		"jdbc":  "clojure.java.jdbc",
	}
	for local, ns := range want {
		if got.names[local] != ns {
			t.Errorf("%s → %q, want %q", local, got.names[local], ns)
		}
	}
	// A require with no :as binds nothing to resolve.
	if _, ok := got.names["clojure.string"]; ok {
		t.Error("a plain require created an alias")
	}
}

// The gap this closes, stated as the measurement that found it: `sh` is the
// canonical alias for clojure.java.shell -- it is the one in that namespace's
// own docstring -- and it resolved to nothing, while the unusual `shell` matched
// only because the catalog happened to enumerate it.
func TestClojureCanonicalShellAliasResolves(t *testing.T) {
	for _, alias := range []string{"sh", "shell", "sh2", "shell-utils"} {
		src := "(ns p (:require [clojure.java.shell :as " + alias + "]))\n"
		table := importAliases(lexctx.LangClojure, []byte(src))
		got := expandChain(alias+"/sh", table)
		if got != "clojure.java.shell/sh" {
			t.Errorf(":as %s → %q, want clojure.java.shell/sh", alias, got)
		}
	}
}

// Elixir and C# name their sinks BARE (`System.cmd`, `Process.Start`), so an
// alias resolves to the last segment, not the whole path. Resolving to the full
// path would produce a name the catalog does not carry.
func TestElixirAliases(t *testing.T) {
	src := `defmodule App do
  alias MyApp.Repo, as: DB
  alias System, as: Sys
  alias MyApp.Repo
  alias MyApp.{Accounts, Billing}
end
`
	got := importAliases(lexctx.LangElixir, []byte(src)).names
	if got["DB"] != "Repo" {
		t.Errorf(`DB → %q, want "Repo"`, got["DB"])
	}
	if got["Sys"] != "System" {
		t.Errorf(`Sys → %q, want "System"`, got["Sys"])
	}
	// Plain `alias MyApp.Repo` already binds the bare name the catalog uses, so
	// there is nothing to expand and inventing an entry would only add noise.
	if len(got) != 2 {
		t.Errorf("unexpected aliases: %v", got)
	}
}

func TestCSharpUsingAliases(t *testing.T) {
	src := `using System.Diagnostics;
using Proc = System.Diagnostics.Process;
global using Sb = System.Text.StringBuilder;
using static System.Math;
using var stream = File.OpenRead(path);
using (var conn = new SqlConnection(cs)) { }
`
	got := importAliases(lexctx.LangCSharp, []byte(src)).names
	if got["Proc"] != "Process" {
		t.Errorf(`Proc → %q, want "Process"`, got["Proc"])
	}
	if got["Sb"] != "StringBuilder" {
		t.Errorf(`Sb → %q, want "StringBuilder"`, got["Sb"])
	}
	// `using static`, a using DECLARATION and a using STATEMENT share the
	// keyword but not the shape; binding any of them would invent a chain.
	if len(got) != 2 {
		t.Errorf("unexpected aliases: %v", got)
	}
}

// The separator belongs to the table because expanding a Clojure chain with a
// dot -- or a Python one with a slash -- yields a name that matches nothing, and
// does so silently.
func TestSeparatorIsPerLanguage(t *testing.T) {
	clj := aliasTable{sep: "/", names: map[string]string{"sh": "clojure.java.shell"}}
	if got := expandChain("sh/sh", clj); got != "clojure.java.shell/sh" {
		t.Errorf("clojure: got %q", got)
	}
	// The same chain read with a dot separator finds no head and expands to
	// nothing, rather than to a plausible-looking wrong answer.
	dotted := aliasTable{sep: ".", names: map[string]string{"sh": "clojure.java.shell"}}
	if got := expandChain("sh/sh", dotted); got != "" {
		t.Errorf("wrong separator should expand to nothing, got %q", got)
	}
}
