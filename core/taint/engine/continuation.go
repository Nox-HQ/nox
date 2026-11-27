package engine

import (
	"bytes"
	"strings"

	"github.com/nox-hq/nox/core/lexctx"
)

// Trailing-operator continuation, for the languages whose statements end at a
// newline or a semicolon and that have no tree-sitter front end: Perl,
// PowerShell, Objective-C, Lua, Elixir, Dart and Groovy.
//
// The line segmenter continues a line only while a bracket is open, so a
// statement split after an operator,
//
//	local cmd = "ls " ..
//	    os.getenv("DIR")
//	os.execute(cmd)
//
// was two statements: cmd was assigned a constant and the flow was lost. In
// each of these languages a line whose code ends in a binary operator or an
// assignment cannot end the statement (an operand must follow), so the next
// line is joined. That is the whole of what a parse tree would add here: a
// probe of each language found the operator and the initializer continued on
// the next line lost, and nothing else that a bracket count misses.
//
// Each language lists only operators that cannot end a statement in it. Left
// out, among others: `/` and `//` in Perl (a regex or substitution ends with
// one), `?` in Dart and Groovy (a nullable type), `->` in Elixir and Groovy
// (a clause or closure opens a body), `,` everywhere (a list is bracketed,
// and a bracket already continues the line), and `*` and `-` (a pointer
// declarator, a negative literal). Comments and strings are blanked first, so
// an operator inside one never counts -- but a string is an operand, so it is
// kept as one: blanked like a comment, `c = "ls"` would read as `c =`.
type continuationOps struct {
	ops   []string // symbol operators, matched as the line's last characters
	words []string // word operators, matched as the last word
}

var (
	perlContinuation       = continuationOps{ops: []string{"=", ".", "+", "&&", "||"}, words: []string{"and", "or"}}
	powerShellContinuation = continuationOps{ops: []string{"=", "+", "|", "`"}, words: []string{"-and", "-or"}}
	objcContinuation       = continuationOps{ops: []string{"=", "+", "&&", "||"}}
	luaContinuation        = continuationOps{ops: []string{"=", "..", "+"}, words: []string{"and", "or"}}
	elixirContinuation     = continuationOps{ops: []string{"=", "<>", "++", "+", "&&", "||", "|>"}, words: []string{"and", "or"}}
	dartContinuation       = continuationOps{ops: []string{"=", "+", "&&", "||", "??", "=>"}}
	groovyContinuation     = continuationOps{ops: []string{"=", "+", "&&", "||", "?:", "<<"}}
)

// trailingOperatorJoins reports, for each physical line (1-based), whether its
// code ends in one of c's operators, so the next line continues it.
func trailingOperatorJoins(content []byte, regions []lexctx.Region, c continuationOps) func(line int) bool {
	join := map[int]bool{}
	for i, line := range bytes.Split(operandMask(content, regions), []byte("\n")) {
		if c.endsInOperator(strings.TrimRight(string(line), " \t\r")) {
			join[i+1] = true
		}
	}
	return func(line int) bool { return join[line] }
}

func (c continuationOps) endsInOperator(code string) bool {
	for _, op := range c.ops {
		if strings.HasSuffix(code, op) {
			return true
		}
	}
	for _, w := range c.words {
		if !strings.HasSuffix(code, w) {
			continue
		}
		before := strings.TrimSuffix(code, w)
		if before == "" || !isIdentByte(before[len(before)-1]) {
			return true
		}
	}
	return false
}

// operandMask is content with each comment byte blanked and each string byte
// replaced by a letter, so a line ending in a string literal ends in an
// operand and one ending in a comment ends where its code does.
func operandMask(content []byte, regions []lexctx.Region) []byte {
	m := make([]byte, len(content))
	for i := range content {
		switch {
		case content[i] == '\n':
			m[i] = '\n'
		case lexctx.KindAt(regions, i) == lexctx.KindCode:
			m[i] = content[i]
		case lexctx.KindAt(regions, i) == lexctx.KindString:
			m[i] = 's'
		default:
			m[i] = ' '
		}
	}
	return m
}
