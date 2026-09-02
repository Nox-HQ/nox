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

// importAliases maps a local name to the qualified path it refers to.
//
// A value may be a module ("os", "child_process") or a fully qualified member
// ("os.system"), which is why callers must join the remainder of a chain onto
// it rather than assuming one or the other.
func importAliases(lang lexctx.Lang, content []byte) map[string]string {
	switch lang {
	case lexctx.LangPython:
		return pythonAliases(content)
	case lexctx.LangJavaScript:
		return javascriptAliases(content)
	default:
		// Every other language keeps today's behaviour. Go resolves its own
		// aliases in the AST extractor; the rest are unmeasured, and adding
		// guesses for import syntaxes nobody has checked would be the same
		// mistake in a new place.
		return nil
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

// expandChain returns the qualified form of a dotted chain, or "" when the head
// is not an imported name.
//
// `system` with system→os.system becomes "os.system"; `o.system` with o→os
// becomes "os.system"; `cp.exec` with cp→child_process becomes
// "child_process.exec".
func expandChain(chain string, aliases map[string]string) string {
	if len(aliases) == 0 || chain == "" {
		return ""
	}
	head, rest, _ := strings.Cut(chain, ".")
	qualified, ok := aliases[head]
	if !ok {
		return ""
	}
	if rest == "" {
		return qualified
	}
	return qualified + "." + rest
}

// applyImportAliases adds the qualified form of every call and chain a statement
// records, so a catalog entry naming the module path matches a call written
// through an alias or a destructured import.
//
// Additions only: see the package note on why nothing is replaced.
func applyImportAliases(drafts []unitDraft, aliases map[string]string) {
	if len(aliases) == 0 {
		return
	}
	for i := range drafts {
		for j := range drafts[i].stmts {
			st := &drafts[i].stmts[j]
			st.calls = withExpansions(st.calls, aliases)
			st.chains = withExpansions(st.chains, aliases)
			expandSinkArgs(st, aliases)
		}
	}
}

// withExpansions returns the list plus any qualified forms not already present.
func withExpansions(in []string, aliases map[string]string) []string {
	if len(in) == 0 {
		return in
	}
	seen := make(map[string]struct{}, len(in))
	for _, c := range in {
		seen[c] = struct{}{}
	}
	out := in
	for _, c := range in {
		expanded := expandChain(c, aliases)
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
func expandSinkArgs(st *stmtDraft, aliases map[string]string) {
	if len(st.sinkArgs) == 0 {
		return
	}
	for call, info := range st.sinkArgs {
		expanded := expandChain(call, aliases)
		if expanded == "" {
			continue
		}
		if _, exists := st.sinkArgs[expanded]; exists {
			continue
		}
		st.sinkArgs[expanded] = info
	}
}
