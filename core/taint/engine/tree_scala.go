package engine

import "github.com/nox-hq/nox/core/lexctx"

// The tree-sitter front end for Scala (ADR 0006, rule 4), the Java one's
// technique (tree_java.go). Scala ends a statement at the newline when it can,
// so a statement continued with a trailing operator,
//
//	val q = "SELECT * FROM users " +
//	        "WHERE id = " + id
//
// was two statements to the line segmenter: no bracket is open at the end of
// the first, so q never read id.
//
// What the tree joins is the operator expression itself, a multi-line
// `infix_expression`, and nothing wider, as in Ruby (tree_ruby.go). Joining whole
// statements, as the Java front end does, was probed and rejected: a method
// chain
//
//	val r = st
//	  .executeQuery("SELECT count(*) FROM t")
//	  .withLabel(id)
//
// became one statement that reads the tainted `id` and calls the sink with a
// constant, a flow the code does not have. A binary expression holds no call
// chain of its own, so it adds no such pair. A binary that holds a block or a
// closure keeps the line segmenter's handling, which follows its braces.

var scalaStatementKinds = map[string]bool{"infix_expression": true}

// scalaBodyKinds hold statements of their own: a method, closure or case
// body, a class or object body, an indented block (Scala 3).
var scalaBodyKinds = map[string]bool{
	"block": true, "template_body": true, "indented_block": true,
	"case_block": true, "enum_body": true, "indented_cases": true,
}

func scalaTreeLines(content []byte, regions []lexctx.Region) ([]logicalLine, bool) {
	return treeJoinedLines("scala", scalaStatementKinds, scalaBodyKinds, content, regions)
}
