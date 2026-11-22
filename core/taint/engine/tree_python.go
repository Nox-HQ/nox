package engine

import (
	"bytes"
	"context"
	"os"
	"strings"
	"sync"

	"github.com/nox-hq/nox/core/lexctx"
	"github.com/nox-hq/nox/core/treesitter"
)

// The tree-sitter front end for Python (ADR 0006, rule 4).
//
// It does not replace extraction. It replaces SEGMENTATION: where a statement
// starts and ends, which lines head a block, and what belongs to a block.
// extractPython consumes the same logicalLines it gets from the line
// segmenter, and every statement's facts are still read by the same
// recognizers, so the units differ only where the line segmenter guessed a
// boundary the grammar knows:
//
//   - `a = f(); os.system(a)` is two statements, not one;
//   - `if x: os.system(y)` is a header and a one-line body inside it, not a
//     single statement outside any block;
//   - a decorator, a header and its parameters are read as the grammar
//     delimits them, whatever the bracket nesting or continuation style.
//
// A file the parser declines (too large, out of time, an error tree, a
// trap) falls back to the line segmenter, which is how every file was
// segmented before; the decline is the file's, never the scan's.
//
// On by default, after an A/B (ADR 0006, rule 4): of 2,101 Python files in
// the RealVuln corpus, 2,076 produced identical units; on the repositories
// holding the other 24, two labelled findings were gained and none lost.

var (
	treeParserOnce sync.Once
	treeParser     *treesitter.Parser
)

func sharedTreeParser() *treesitter.Parser {
	treeParserOnce.Do(func() {
		p, err := treesitter.NewParser(context.Background())
		if err == nil {
			treeParser = p
		}
	})
	return treeParser
}

// treeFrontEndDefault are the languages the tree-sitter front end segments.
var treeFrontEndDefault = []string{"python", "javascript", "java"}

// treeFrontEnd reports whether the tree-sitter front end segments lang.
// NOX_TAINT_TREESITTER, when set, replaces the default list ("none" for no
// language): it exists to A/B a front end against the line segmenter on the
// same binary, the way each language is switched over.
func treeFrontEnd(lang string) bool {
	langs := treeFrontEndDefault
	if v, ok := os.LookupEnv("NOX_TAINT_TREESITTER"); ok {
		langs = strings.Split(v, ",")
	}
	for _, l := range langs {
		if strings.TrimSpace(l) == lang {
			return true
		}
	}
	return false
}

// pyTreeLines returns the logical lines of a Python source from its parse
// tree, or false when the parser declines the file.
func pyTreeLines(content []byte, regions []lexctx.Region) ([]logicalLine, bool) {
	p := sharedTreeParser()
	if p == nil {
		return nil, false
	}
	tree, lim := p.ParseFile(context.Background(), "python", content, treesitter.Budget{})
	if lim != nil {
		return nil, false
	}
	s := pySegmenter{content: content, tree: tree, codeMask: codeMaskOf(content, regions), lineStarts: lineStartsOf(content)}
	s.children = make([][]int, len(tree.Nodes))
	for i, n := range tree.Nodes {
		if n.Parent >= 0 {
			s.children[n.Parent] = append(s.children[n.Parent], i)
		}
	}
	s.block(0, "")
	return s.out, true
}

// codeMaskOf is content with every non-code byte (strings, comments) a space,
// newlines kept: the code view logicalLines builds.
func codeMaskOf(content []byte, regions []lexctx.Region) []byte {
	m := make([]byte, len(content))
	for i := range content {
		switch {
		case content[i] == '\n':
			m[i] = '\n'
		case lexctx.KindAt(regions, i) == lexctx.KindCode:
			m[i] = content[i]
		default:
			m[i] = ' '
		}
	}
	return m
}

func lineStartsOf(content []byte) []int {
	starts := []int{0}
	for i, c := range content {
		if c == '\n' {
			starts = append(starts, i+1)
		}
	}
	return starts
}

type pySegmenter struct {
	content, codeMask []byte
	lineStarts        []int
	tree              *treesitter.Tree
	children          [][]int
	out               []logicalLine
}

// row is the 0-based line holding byte off.
func (s *pySegmenter) row(off uint32) int {
	lo, hi := 0, len(s.lineStarts)-1
	for lo < hi {
		mid := (lo + hi + 1) / 2
		if s.lineStarts[mid] <= int(off) {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	return lo
}

// indentOf is the leading whitespace of the line holding off.
func (s *pySegmenter) indentOf(off uint32) string {
	start := s.lineStarts[s.row(off)]
	end := start
	for end < len(s.content) && (s.content[end] == ' ' || s.content[end] == '\t') {
		end++
	}
	return string(s.content[start:end])
}

// emit appends the logical line for bytes [start, end) with the given
// indentation. Newlines inside the span become spaces, as the line
// segmenter joins continuation lines.
func (s *pySegmenter) emit(start, end uint32, indent string) {
	if end <= start {
		return
	}
	// Only '\n' becomes a space; a '\r' stays, as the line segmenter keeps it.
	flat := func(b []byte) string { return string(bytes.ReplaceAll(b, []byte("\n"), []byte(" "))) }
	s.out = append(s.out, logicalLine{
		line: s.row(start) + 1,
		code: indent + flat(s.codeMask[start:end]),
		raw:  indent + flat(s.content[start:end]),
	})
}

// block emits the statements of a module or block node. indent, when not
// empty, overrides the source indentation: a one-line body (`if x: y`) is
// given one level more than its header, which is what nests it.
func (s *pySegmenter) block(i int, indent string) {
	for _, c := range s.children[i] {
		n := s.tree.Nodes[c]
		if !n.Named || n.Kind == "comment" {
			continue
		}
		s.statement(c, indent)
	}
}

// statement emits one statement: a simple statement as one logical line, a
// compound one as its header line followed by its body and clauses.
func (s *pySegmenter) statement(i int, indent string) {
	n := s.tree.Nodes[i]
	if indent == "" {
		indent = s.indentOf(n.Start)
	}
	body := -1
	for _, c := range s.children[i] {
		if s.tree.Nodes[c].Kind == "block" {
			body = c
			break
		}
	}
	if body < 0 {
		// decorated_definition: its decorators, then the definition itself.
		if n.Kind == "decorated_definition" {
			for _, c := range s.children[i] {
				if cn := s.tree.Nodes[c]; cn.Named && cn.Kind != "comment" {
					s.statement(c, indent)
				}
			}
			return
		}
		s.emit(n.Start, n.End, indent)
		return
	}
	// The header: from the statement's start to its body, the colon included.
	s.emit(n.Start, s.tree.Nodes[body].Start, indent)
	bodyIndent := ""
	if s.row(s.tree.Nodes[body].Start) == s.row(n.Start) {
		bodyIndent = indent + "    "
	}
	seenBody := false
	for _, c := range s.children[i] {
		cn := s.tree.Nodes[c]
		switch {
		case c == body:
			s.block(c, bodyIndent)
			seenBody = true
		case seenBody && cn.Named && cn.Kind != "comment":
			// elif, else, except, finally, case: a clause after the body, at
			// the statement's own level.
			s.statement(c, "")
		}
	}
}
