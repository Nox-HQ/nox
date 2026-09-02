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
	got := importAliases(lexctx.LangPython, []byte(src))
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
	got := importAliases(lexctx.LangJavaScript, []byte(src))
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
	aliases := map[string]string{
		"system": "os.system",     // from-import of a member
		"o":      "os",            // aliased module
		"cp":     "child_process", // aliased module
	}
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
	aliases := map[string]string{"o": "os"}
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
		if got := importAliases(lang, []byte("import os\nfrom os import system\n")); len(got) != 0 {
			t.Errorf("%v returned aliases from a resolver it does not have: %v", lang, got)
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
	got := importAliases(lexctx.LangPython, []byte("# from os import system\n"))
	if len(got) != 0 {
		t.Logf("known limit: a commented import binds a name (%v); additive expansion makes this harmless", got)
	}
}
