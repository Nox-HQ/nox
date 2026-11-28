package engine

import "github.com/nox-hq/nox/core/lexctx"

// The tree-sitter front end for C (ADR 0006, rule 4), for .c files only; C++
// and headers keep the line segmenter. C ends a statement at the semicolon,
// but the line segmenter reads a line as a statement unless a bracket is
// open, so a declaration whose initializer starts on the next line,
//
//	char *cmd =
//	    getenv("CMD");
//	system(cmd);
//
// was two statements: cmd was assigned from nothing and the flow was lost.
// The same for a cast, a ternary or an operator continued on the next line,
// and a return whose value does.
//
// What the tree joins is a whole statement, as in Java (tree_java.go): C has
// no method chains, the shape that made Ruby, Scala, Swift and Rust join only
// binary expressions (a chain read whole put a constant-argument sink and a
// tainted receiver argument in one statement). A declaration is joined per
// declarator, as in JavaScript: `char *a = f(),\n *b = g(a);` is two
// bindings. A statement holding a block (a GNU statement expression) or an
// initializer list (a table of entries) keeps the line segmenter's handling.
//
// Error trees. A C file is parsed without its preprocessor, so an unknown
// macro or a conditional inside a statement is an ERROR node: 53% of the .c
// files of the corpus parse with one, busybox 94%. Error recovery marks what
// it shaped with ERROR and MISSING nodes, and a statement whose extent holds
// neither was built by the grammar's rules (the guesses it makes, such as a
// declaration taking in the next line, carry the marks; the tests pin two).
// The tree only adds joins to the line segmenter's lines. So a join is taken from a
// statement that holds no ERROR or MISSING node and lies inside no ERROR
// node, and the rest of the file is read by the line segmenter as before: an
// error costs the statements it touches, not the file (ADR 0006, rule 3,
// amended 2026-11-27).

var cStatementKinds = map[string]bool{
	"init_declarator": true, "expression_statement": true, "return_statement": true,
}

var cBodyKinds = map[string]bool{
	"compound_statement": true, "initializer_list": true,
	"field_declaration_list": true, "enumerator_list": true,
}

func cTreeLines(content []byte, regions []lexctx.Region) ([]logicalLine, bool) {
	return treeJoinedLinesFrom("c", cStatementKinds, cBodyKinds, content, regions, true)
}
