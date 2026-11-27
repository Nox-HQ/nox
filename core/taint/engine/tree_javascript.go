package engine

import (
	"context"
	"path/filepath"
	"strings"

	"github.com/nox-hq/nox/core/lexctx"
	"github.com/nox-hq/nox/core/treesitter"
)

// The tree-sitter front end for JavaScript and TypeScript (ADR 0006, rule 4).
//
// The JavaScript extractor tracks function bodies by counting braces line by
// line, and a callback opens a body in the middle of a call
// (`app.get('/', (req, res) => {`), so the tree cannot hand it whole
// statements the way the Python front end does. It supplies one fact the
// line segmenter cannot see: which physical lines are one statement. A line
// is joined to the next only inside an open bracket today, so
//
//	const q = "SELECT * FROM t WHERE id = " +
//	  req.query.id;
//
// became two statements, and q never read the request. Every statement the
// grammar delimits -- a declaration, an expression statement, a return or a
// throw, and each declarator of a declaration -- that spans lines and holds no
// function or class body has its lines joined; everything else is segmented
// exactly as before.
//
// On by default after an A/B on all 203 RealVuln repositories, the same
// binary with and without it: +7 labelled findings (SQL concatenated across
// lines into db.exec and $queryRawUnsafe, an open redirect, an XSS), none
// lost, 41 unmatched added -- JSON replies read as HTML and file paths from
// records looked up by a request id, precision gaps the completed flows now
// reach, not segmentation errors.

// jsGrammar is the grammar a JavaScript-family file parses with.
func jsGrammar(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".ts", ".mts", ".cts":
		return "typescript"
	case ".tsx":
		return "tsx"
	}
	return "javascript"
}

// jsStatementKinds are the statements whose lines are joined. A declaration
// is joined per declarator instead: `var a = f(),\n b = g(a);` is two
// bindings, which the line segmenter already reads one per line, and joining
// the whole declaration would make it one statement assigning a and reading
// everything -- taint from any declarator flowing into the first.
var jsStatementKinds = map[string]bool{
	"variable_declarator": true, "expression_statement": true,
	"return_statement": true, "throw_statement": true,
}

// jsBodyKinds hold statements of their own; a statement containing one keeps
// the line segmenter's handling, which follows its braces.
var jsBodyKinds = map[string]bool{"statement_block": true, "class_body": true}

// jsTreeLines returns the logical lines of a JavaScript-family source with the
// tree's statement extents joined, or false when the parser declines it.
func jsTreeLines(path string, content []byte, regions []lexctx.Region) ([]logicalLine, bool) {
	return treeJoinedLines(jsGrammar(path), jsStatementKinds, jsBodyKinds, content, regions)
}

// treeJoinedLines returns the logical lines of a brace-delimited source with
// the physical lines of each statement of stmtKinds joined, unless it holds a
// node of bodyKinds; false when the parser declines the file. The grammar is
// a treesitter language name.
func treeJoinedLines(grammar string, stmtKinds, bodyKinds map[string]bool, content []byte, regions []lexctx.Region) ([]logicalLine, bool) {
	return treeJoinedLinesFrom(grammar, stmtKinds, bodyKinds, content, regions, false)
}

// treeJoinedLinesFrom is treeJoinedLines; with localErrors it also uses an
// error tree, taking joins only from statements that hold no ERROR or MISSING
// node and lie inside no ERROR node (see tree_c.go for why that is sound).
func treeJoinedLinesFrom(grammar string, stmtKinds, bodyKinds map[string]bool, content []byte, regions []lexctx.Region, localErrors bool) ([]logicalLine, bool) {
	p := sharedTreeParser()
	if p == nil {
		return nil, false
	}
	tree, lim := p.ParseFile(context.Background(), grammar, content, treesitter.Budget{})
	// An error tree is used only by a caller that takes joins locally.
	usable := lim == nil || (localErrors && lim.Reason == treesitter.ReasonErrorTree && tree != nil)
	if !usable {
		return nil, false
	}
	join := treeLineJoins(tree, content, stmtKinds, bodyKinds)
	return logicalLinesJoined(content, regions, true, nil, func(l int) bool { return join[l] }), true
}

// treeLineJoins is the set of physical lines (1-based) to join with the next:
// every line but the last of each statement of stmtKinds that holds no node
// of bodyKinds, no ERROR or MISSING node, and lies inside no ERROR node. On a
// clean tree the last two never hold.
func treeLineJoins(tree *treesitter.Tree, content []byte, stmtKinds, bodyKinds map[string]bool) map[int]bool {
	// inError[i]: node i lies inside an ERROR node. Parents come first.
	inError := make([]bool, len(tree.Nodes))
	for i, n := range tree.Nodes {
		inError[i] = n.Error || (n.Parent >= 0 && inError[n.Parent])
	}
	// hasBody[i]: node i contains a function or class body. Records are in
	// pre-order with parents earlier, so one backward pass carries it up.
	hasBody := make([]bool, len(tree.Nodes))
	for i := len(tree.Nodes) - 1; i > 0; i-- {
		if hasBody[i] || bodyKinds[tree.Nodes[i].Kind] {
			hasBody[tree.Nodes[i].Parent] = true
		}
	}
	starts := lineStartsOf(content)
	row := func(off uint32) int { // 1-based
		lo, hi := 0, len(starts)-1
		for lo < hi {
			mid := (lo + hi + 1) / 2
			if starts[mid] <= int(off) {
				lo = mid
			} else {
				hi = mid - 1
			}
		}
		return lo + 1
	}
	join := map[int]bool{}
	for i, n := range tree.Nodes {
		if !stmtKinds[n.Kind] || hasBody[i] || n.End <= n.Start || n.HasError || inError[i] {
			continue
		}
		first, last := row(n.Start), row(n.End-1)
		for l := first; l < last; l++ {
			join[l] = true
		}
	}
	return join
}
