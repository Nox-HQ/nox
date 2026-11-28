package engine

import "github.com/nox-hq/nox/core/lexctx"

// The tree-sitter front end for Swift (ADR 0006, rule 4), the Java one's
// technique (tree_java.go). Swift ends a statement at the newline when it can,
// so a statement continued with a trailing operator,
//
//	let q = "SELECT * FROM users " +
//	        "WHERE id = " + id
//
// was two statements to the line segmenter: no bracket is open at the end of
// the first, so q never read id.
//
// What the tree joins is the operator expression itself, a multi-line
// `additive_expression`, and nothing wider, as in Ruby (tree_ruby.go). Joining whole
// statements, as the Java front end does, was probed and rejected: a method
// chain
//
//	let r = fm
//	  .removeItem(atPath: "/tmp/static")
//	  .label(id)
//
// became one statement that reads the tainted `id` and calls the sink with a
// constant, a flow the code does not have. A binary expression holds no call
// chain of its own, so it adds no such pair. A binary that holds a block or a
// closure keeps the line segmenter's handling, which follows its braces.

var swiftStatementKinds = map[string]bool{"additive_expression": true}

// swiftBodyKinds hold statements of their own: a function or closure body, a
// type body, a computed property, a switch case.
var swiftBodyKinds = map[string]bool{
	"function_body": true, "lambda_literal": true, "class_body": true,
	"enum_class_body": true, "protocol_body": true, "computed_property": true,
	"statements": true,
}

func swiftTreeLines(content []byte, regions []lexctx.Region) ([]logicalLine, bool) {
	return treeJoinedLines("swift", swiftStatementKinds, swiftBodyKinds, content, regions)
}
