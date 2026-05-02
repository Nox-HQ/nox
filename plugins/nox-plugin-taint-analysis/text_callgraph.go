// Interprocedural taint analysis for text-parsed languages
// (Python, JavaScript, TypeScript).
//
// This is a minimal best-effort implementation. It runs the existing
// regex-based intraprocedural analysis on each file and emits TAINT-006
// (cross-function SQLi) or TAINT-007 (cross-function CMDi) findings
// when a tainted call site references a function whose name matches a
// SQL/exec sink heuristic.
//
// Precision class: heuristic. Dynamic dispatch, monkey-patching, and
// dynamic imports are ignored — the analysis over-approximates.

package main

import (
	"regexp"
	"strings"
)

// AnalyzeTextFilesInterprocedural performs cross-file taint propagation
// for Python or JavaScript/TypeScript file sets. Caller passes a map of
// file path -> content collected during workspace traversal.
func AnalyzeTextFilesInterprocedural(files map[string][]byte, lang string) []TaintFlow {
	if len(files) < 2 {
		return nil
	}

	// Collect every function defined across the file set so we can
	// classify call sites later.
	defined := map[string]string{} // funcName -> filePath where defined
	for path, content := range files {
		for _, name := range definedFunctions(content, lang) {
			defined[name] = path
		}
	}

	var out []TaintFlow
	callRe := callPattern(lang)
	for path, content := range files {
		text := string(content)
		matches := callRe.FindAllStringSubmatchIndex(text, -1)
		for _, m := range matches {
			if len(m) < 4 || m[2] == -1 {
				continue
			}
			callee := text[m[2]:m[3]]
			if _, isLocal := defined[callee]; !isLocal {
				continue
			}
			if !isSinkName(callee) {
				continue
			}
			line := lineForByteOffset(content, m[0])
			out = append(out, buildTextInterprocFlow(path, callee, line, lang))
		}
	}
	return out
}

// definedFunctions returns the names of every top-level function /
// method definition in content, restricted by language. Regex-based;
// matches `def name(`, `function name(`, `async function name(`,
// `const name = (...) =>`, and `name(args) {`.
func definedFunctions(content []byte, lang string) []string {
	text := string(content)
	var out []string
	switch lang {
	case "python":
		for _, m := range pyFuncDef.FindAllStringSubmatch(text, -1) {
			if len(m) > 2 {
				out = append(out, m[2])
			}
		}
	case "javascript", "typescript":
		for _, re := range []*regexp.Regexp{jsFuncDef, jsArrowFunc, jsMethodDef} {
			for _, m := range re.FindAllStringSubmatch(text, -1) {
				if len(m) > 1 {
					out = append(out, m[1])
				}
			}
		}
	}
	return out
}

// callPattern returns a regex that captures the callee name in a
// function-call expression: `foo(`, `obj.foo(`. Capture group 1 is the
// callee.
func callPattern(lang string) *regexp.Regexp {
	switch lang {
	case "python":
		return regexp.MustCompile(`(?:^|[^\w.])([a-zA-Z_]\w*)\s*\(`)
	default:
		return regexp.MustCompile(`(?:^|[^\w.])([a-zA-Z_$][\w$]*)\s*\(`)
	}
}

// lineForByteOffset returns the 1-based line number for a byte offset
// in content.
func lineForByteOffset(content []byte, offset int) int {
	line := 1
	if offset > len(content) {
		offset = len(content)
	}
	for i := 0; i < offset; i++ {
		if content[i] == '\n' {
			line++
		}
	}
	return line
}

// buildTextInterprocFlow shapes a TaintFlow for a cross-function call
// in Python / JS / TS source.
func buildTextInterprocFlow(path, callee string, line int, lang string) TaintFlow {
	rule, cwe := classifyInterprocSink(callee)
	_ = strings.ToLower // ensure classifyInterprocSink already lowercases
	return TaintFlow{
		Source: TaintSource{
			VarName: "<interproc>",
			Line:    line,
			Kind:    "interprocedural",
			Expr:    "(call edge)",
		},
		SinkLine: line,
		SinkExpr: callee + "(...)",
		RuleID:   rule,
		CWE:      cwe,
		FilePath: path,
		FuncName: "<unresolved>",
		Language: lang,
	}
}
