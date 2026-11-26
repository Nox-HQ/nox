package engine

import "github.com/nox-hq/nox/core/lexctx"

// The tree-sitter front end for Rust (ADR 0006, rule 4), the Java one's
// technique (tree_java.go). Rust ends a statement at the semicolon, but the
// line segmenter reads a line as a statement unless a bracket is open, so an
// operator continued on the next line,
//
//	let q = String::from("SELECT * FROM users WHERE id = ")
//	    + &id;
//
// was two statements: q never read id.
//
// What the tree joins is the operator expression itself, a multi-line
// `binary_expression`, and nothing wider, as in Ruby (tree_ruby.go). Joining whole
// statements, as the Java front end does, was probed and rejected: a method
// chain
//
//	let r = sqlx::query("SELECT count(*) FROM t")
//	    .label(&id)
//	    .fetch_all(pool);
//
// became one statement that reads the tainted `id` and calls the sink with a
// constant, a flow the code does not have. A binary expression holds no call
// chain of its own, so it adds no such pair. A binary that holds a block or a
// closure keeps the line segmenter's handling, which follows its braces.

var rustStatementKinds = map[string]bool{"binary_expression": true}

// rustBodyKinds hold statements of their own: a function, closure or loop
// body, an impl or trait body, a match.
var rustBodyKinds = map[string]bool{
	"block": true, "declaration_list": true, "match_block": true,
	"field_declaration_list": true, "enum_variant_list": true,
}

func rustTreeLines(content []byte, regions []lexctx.Region) ([]logicalLine, bool) {
	return treeJoinedLines("rust", rustStatementKinds, rustBodyKinds, content, regions)
}
