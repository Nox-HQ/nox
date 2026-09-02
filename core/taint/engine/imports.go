package engine

import (
	"regexp"
	"strings"

	"github.com/nox-hq/nox/core/lexctx"
)

// Import resolution for the recognizer-based extractors.
//
// # The gap this closes
//
// The taint catalog names sinks by their qualified dotted path — `os.system`,
// `child_process.exec`, `subprocess.run` — and the recognizers recorded the call
// chain exactly as written. So a sink matched only when the local name in the
// source happened to equal the module name:
//
//	import os                                  os.system(...)      MATCHED
//	import os as o                             o.system(...)       missed
//	from os import system                      system(...)         missed
//
//	const child_process = require('child_process')   .exec(...)    MATCHED
//	const cp = require('child_process')              cp.exec(...)  missed
//	const { exec } = require('child_process')        exec(...)     missed
//	import { exec } from 'child_process'             exec(...)     missed
//	import cp from 'child_process'                   cp.exec(...)  missed
//
// The one shape that worked is the one almost nobody writes. `from os import
// system`, `import numpy as np` and destructured requires are the ordinary
// idioms, so taint analysis was silently inert on most real Python and Node
// code — measured as: the same textbook command injection reported only when
// the import was written the unusual way.
//
// Go never had this problem: `extract_go.go` resolves aliases through
// `core/source.ImportAliases`. This brings the recognizer languages up to that.
//
// # The same defect, one layer over: Clojure, Elixir and C#
//
// Those three name their sinks by a MODULE or TYPE name that an alias renames,
// and the catalog handled it by enumerating the aliases its author expected --
// `shell/sh` beside `clojure.java.shell/sh`, `io/reader`, `jdbc/query`. That
// works only for the alias someone anticipated. Measured, varying nothing but
// the `:as`:
//
//	(:require [clojure.java.shell :as shell])   shell/sh   MATCHED (enumerated)
//	(:require [clojure.java.shell :as sh])      sh/sh      missed
//	(:require [clojure.java.shell :as sh2])     sh2/sh     missed
//
// `sh` is the canonical alias -- it is the one in clojure.java.shell's own
// docstring -- so the command-injection sink was invisible on the dominant
// spelling while scoring a match on the unusual one. Resolving `:as` replaces
// the guesswork: any alias reaches the qualified name the catalog already has.
//
// Elixir and C# take the mirror form. Their catalog entries are BARE module and
// type names (`System.cmd`, `Repo.query`, `Process.Start`), which is what
// unaliased code writes, so the resolution target is the LAST segment of the
// alias's right-hand side rather than the whole path:
//
//	alias MyApp.Repo, as: DB           DB.query    -> Repo.query
//	using Proc = System.Diagnostics.Process;   Proc.Start -> Process.Start
//
// Known limit, stated rather than papered over: a C# alias that names a
// NAMESPACE (`using D = System.Diagnostics;` then `D.Process.Start`) resolves to
// neither the bare nor the fully-qualified form the catalog carries, and is
// still missed. The common type-alias case is what this handles.
//
// # Why it adds chains rather than replacing them
//
// An expansion is recorded ALONGSIDE the original chain, never instead of it.
// Nothing that matched before can stop matching, so the change cannot remove a
// finding; it can only let a call that was already written be recognised for
// what it is. A local function that shadows an imported name costs a redundant
// chain, not a lost one.

// pyImport matches Python's two import forms, capturing module, names and alias.
var (
	pyPlainImport = regexp.MustCompile(`^\s*import\s+([A-Za-z_][\w.]*)(?:\s+as\s+([A-Za-z_]\w*))?\s*$`)
	pyFromImport  = regexp.MustCompile(`^\s*from\s+([A-Za-z_][\w.]*)\s+import\s+(.+)$`)

	// jsRequire matches `const x = require('mod')` and
	// `const { a, b: c } = require('mod')`, plus let/var.
	jsRequire = regexp.MustCompile(`^\s*(?:const|let|var)\s+(\{[^}]*\}|[A-Za-z_$][\w$]*)\s*=\s*require\(\s*['"]([^'"]+)['"]\s*\)`)
	// jsImport matches ESM: `import x from 'mod'`, `import { a, b as c } from
	// 'mod'`, `import * as x from 'mod'`.
	jsImport = regexp.MustCompile(`^\s*import\s+(.+?)\s+from\s*['"]([^'"]+)['"]`)
)

// aliasTable maps a local name to the name it resolves to, together with the
// separator that joins a call chain in this language. The separator travels
// WITH the table because it is a property of the same language decision: a
// Clojure chain is `sh/sh`, a Python one `os.system`, and expanding either with
// the other's separator would silently produce a name that matches nothing.
type aliasTable struct {
	names map[string]string
	sep   string
}

func (t aliasTable) empty() bool { return len(t.names) == 0 }

// importAliases maps a local name to the qualified path it refers to.
//
// A value may be a module ("os", "child_process"), a fully qualified member
// ("os.system"), or -- for the languages whose catalog entries are bare -- a
// simple module or type name ("Process"). Callers join the remainder of a chain
// onto it rather than assuming one or the other.
func importAliases(lang lexctx.Lang, content []byte) aliasTable {
	switch lang {
	case lexctx.LangPython:
		return aliasTable{names: pythonAliases(content), sep: "."}
	case lexctx.LangJavaScript:
		return aliasTable{names: javascriptAliases(content), sep: "."}
	case lexctx.LangClojure:
		return aliasTable{names: clojureAliases(content), sep: "/"}
	case lexctx.LangElixir:
		return aliasTable{names: elixirAliases(content), sep: "."}
	case lexctx.LangCSharp:
		return aliasTable{names: csharpAliases(content), sep: "."}
	default:
		// Every other language keeps today's behaviour. Go resolves its own
		// aliases in the AST extractor; the rest were probed and either show no
		// gap (Rust's `use x as y` already reaches the sink) or name their sinks
		// by a convention no alias renames. Adding guesses for import syntaxes
		// nobody has checked would be the same mistake in a new place.
		return aliasTable{}
	}
}

// pythonAliases reads `import` and `from … import` statements.
func pythonAliases(content []byte) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(string(content), "\n") {
		if m := pyPlainImport.FindStringSubmatch(line); m != nil {
			module, alias := m[1], m[2]
			if alias != "" {
				out[alias] = module
			}
			continue
		}
		m := pyFromImport.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		module, names := m[1], m[2]
		if strings.Contains(names, "*") {
			// `from x import *` binds names this resolver cannot enumerate.
			// Skipping is the safe direction: no expansion, no invented chain.
			continue
		}
		names = strings.Trim(strings.TrimSpace(names), "()")
		for _, part := range strings.Split(names, ",") {
			name, alias := splitAs(part)
			if name == "" {
				continue
			}
			local := alias
			if local == "" {
				local = name
			}
			out[local] = module + "." + name
		}
	}
	return out
}

// javascriptAliases reads CommonJS requires and ESM imports.
func javascriptAliases(content []byte) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(string(content), "\n") {
		if m := jsRequire.FindStringSubmatch(line); m != nil {
			addJSBinding(out, m[1], m[2])
			continue
		}
		if m := jsImport.FindStringSubmatch(line); m != nil {
			addJSBinding(out, strings.TrimSpace(m[1]), m[2])
		}
	}
	return out
}

// addJSBinding records one import clause against its module.
//
// The clause is either a destructuring pattern (`{ exec, spawn: run }`), a
// namespace form (`* as cp`), or a single name bound to the module itself.
func addJSBinding(out map[string]string, clause, module string) {
	clause = strings.TrimSpace(clause)
	switch {
	case strings.HasPrefix(clause, "{"):
		inner := strings.Trim(clause, "{}")
		for _, part := range strings.Split(inner, ",") {
			name, alias := splitJSMember(part)
			if name == "" {
				continue
			}
			local := alias
			if local == "" {
				local = name
			}
			out[local] = module + "." + name
		}
	case strings.HasPrefix(clause, "*"):
		// `import * as cp from 'mod'` — cp IS the module. What remains after the
		// star is `as cp`, which is not the `name as alias` shape splitAs reads.
		fields := strings.Fields(strings.TrimPrefix(clause, "*"))
		if len(fields) == 2 && fields[0] == "as" && isSimpleIdent(fields[1]) {
			out[fields[1]] = module
		}
	default:
		// `const cp = require('mod')` / `import cp from 'mod'`. A default import
		// is not literally the namespace, but for sink matching it is the object
		// whose members the catalog names, which is the question being asked.
		if isSimpleIdent(clause) {
			out[clause] = module
		}
	}
}

// splitAs splits `name as alias`, returning the name and the alias ("" if none).
func splitAs(s string) (name, alias string) {
	fields := strings.Fields(strings.TrimSpace(s))
	switch len(fields) {
	case 1:
		return fields[0], ""
	case 3:
		if fields[1] == "as" {
			return fields[0], fields[2]
		}
	}
	return "", ""
}

// splitJSMember splits a destructured member, which renames with `:` in
// CommonJS (`{ exec: run }`) and with `as` in ESM (`{ exec as run }`).
func splitJSMember(s string) (name, alias string) {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, ":"); i >= 0 {
		return strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+1:])
	}
	return splitAs(s)
}

// clojureAliases reads `:as` (and `:as-alias`) out of ns/require libspecs.
//
// Every alias in Clojure is introduced by the same vector shape --
// `[some.namespace :as local]` -- whether it appears in an `(ns …)` form, a
// top-level `(require '[…])`, or a multi-line `:require` block. One pattern
// covers all three, which is why this is a resolution rather than a list of
// namespaces someone remembered.
var cljAlias = regexp.MustCompile(`\[\s*([A-Za-z][\w.$*+!?<>=-]*)\s+:as(?:-alias)?\s+([A-Za-z][\w.$*+!?<>=-]*)`)

func clojureAliases(content []byte) map[string]string {
	out := map[string]string{}
	for _, m := range cljAlias.FindAllStringSubmatch(string(content), -1) {
		ns, local := m[1], m[2]
		if ns == local {
			continue // nothing to resolve
		}
		out[local] = ns
	}
	return out
}

// elixirAliases reads `alias Some.Module, as: Local`.
//
// Plain `alias MyApp.Repo` is deliberately skipped: it binds `Repo`, which is
// already the bare name the catalog carries, so there is nothing to expand.
var exAlias = regexp.MustCompile(`^\s*alias\s+([A-Z][\w.]*)\s*,\s*as:\s*([A-Z]\w*)`)

func elixirAliases(content []byte) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(string(content), "\n") {
		m := exAlias.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		// The catalog names Elixir sinks bare (`System.cmd`, `Repo.query`), so
		// the target is the last segment, not the whole path.
		if target := lastSegment(m[1], "."); target != m[2] {
			out[m[2]] = target
		}
	}
	return out
}

// csharpAliases reads `using Local = Some.Qualified.Type;`.
//
// The `using var x = …` declaration and `using static …` share the keyword but
// not the shape: both are excluded by requiring a single identifier before the
// `=` and a plain dotted name after it.
var csUsingAlias = regexp.MustCompile(`^\s*(?:global\s+)?using\s+([A-Za-z_]\w*)\s*=\s*([A-Za-z_][\w.]*)\s*;`)

func csharpAliases(content []byte) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(string(content), "\n") {
		m := csUsingAlias.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		// As in Elixir, the catalog names the TYPE (`Process.Start`), so the
		// alias resolves to the last segment.
		if target := lastSegment(m[2], "."); target != m[1] {
			out[m[1]] = target
		}
	}
	return out
}

// lastSegment returns the final component of a separated path.
func lastSegment(s, sep string) string {
	if i := strings.LastIndex(s, sep); i >= 0 {
		return s[i+len(sep):]
	}
	return s
}

// expandChain returns the resolved form of a chain, or "" when the head is not
// an imported name.
//
// `system` with system→os.system becomes "os.system"; `o.system` with o→os
// becomes "os.system"; `cp.exec` with cp→child_process becomes
// "child_process.exec"; `sh/sh` with sh→clojure.java.shell becomes
// "clojure.java.shell/sh".
func expandChain(chain string, t aliasTable) string {
	if t.empty() || chain == "" {
		return ""
	}
	head, rest, _ := strings.Cut(chain, t.sep)
	qualified, ok := t.names[head]
	if !ok {
		return ""
	}
	if rest == "" {
		return qualified
	}
	return qualified + t.sep + rest
}

// applyImportAliases adds the qualified form of every call and chain a statement
// records, so a catalog entry naming the module path matches a call written
// through an alias or a destructured import.
//
// Additions only: see the package note on why nothing is replaced.
func applyImportAliases(drafts []unitDraft, t aliasTable) {
	if t.empty() {
		return
	}
	for i := range drafts {
		for j := range drafts[i].stmts {
			st := &drafts[i].stmts[j]
			st.calls = withExpansions(st.calls, t)
			st.chains = withExpansions(st.chains, t)
			expandSinkArgs(st, t)
		}
	}
}

// withExpansions returns the list plus any qualified forms not already present.
func withExpansions(in []string, t aliasTable) []string {
	if len(in) == 0 {
		return in
	}
	seen := make(map[string]struct{}, len(in))
	for _, c := range in {
		seen[c] = struct{}{}
	}
	out := in
	for _, c := range in {
		expanded := expandChain(c, t)
		if expanded == "" {
			continue
		}
		if _, dup := seen[expanded]; dup {
			continue
		}
		seen[expanded] = struct{}{}
		out = append(out, expanded)
	}
	return out
}

// expandSinkArgs mirrors each per-call argument record under the call's
// qualified name, so the argument shape a sink is judged on survives the
// rewrite. Without it a call would match the catalog by its expanded name and
// then be judged on no argument evidence at all.
func expandSinkArgs(st *stmtDraft, t aliasTable) {
	if len(st.sinkArgs) == 0 {
		return
	}
	for call, info := range st.sinkArgs {
		expanded := expandChain(call, t)
		if expanded == "" {
			continue
		}
		if _, exists := st.sinkArgs[expanded]; exists {
			continue
		}
		st.sinkArgs[expanded] = info
	}
}
