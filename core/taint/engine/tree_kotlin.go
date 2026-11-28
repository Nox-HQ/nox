package engine

import "github.com/nox-hq/nox/core/lexctx"

// The tree-sitter front end for Kotlin (ADR 0006, rule 4), the Java one's
// technique (tree_java.go). Kotlin ends a statement at the newline when it can,
// so a statement continued with a trailing operator,
//
//	val q = "SELECT * FROM users " +
//	        "WHERE id = " + id
//
// was two statements to the line segmenter: no bracket is open at the end of
// the first, so q never read id.
//
// The grammar wraps no statement in a statement node, so the kinds below are
// the expressions that make one. One that holds a lambda or a block keeps the
// line segmenter's handling, which follows its braces.

var kotlinStatementKinds = map[string]bool{
	"property_declaration": true, "assignment": true, "call_expression": true,
	"return_expression": true, "throw_expression": true, "jump_expression": true,
}

// kotlinBodyKinds hold statements of their own: a function or lambda body, a
// class body, a when, an anonymous object.
var kotlinBodyKinds = map[string]bool{
	"block": true, "lambda_literal": true, "class_body": true, "enum_class_body": true,
	"when_expression": true, "anonymous_function": true, "control_structure_body": true,
	"object_literal": true,
}

func kotlinTreeLines(content []byte, regions []lexctx.Region) ([]logicalLine, bool) {
	return treeJoinedLines("kotlin", kotlinStatementKinds, kotlinBodyKinds, content, regions)
}
