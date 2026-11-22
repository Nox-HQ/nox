package engine

import "github.com/nox-hq/nox/core/lexctx"

// The tree-sitter front end for Java (ADR 0006, rule 4), the JavaScript one's
// technique (tree_javascript.go): the Java extractor follows method bodies by
// counting braces, and the tree supplies which physical lines are one
// statement. The shape it exists for is SQL built across lines,
//
//	String q = "SELECT * FROM users " +
//	           "WHERE id = " + id;
//
// which the line segmenter read as two statements: no bracket is open at the
// end of the first, so q never read id.
//
// On by default after an A/B on all 203 RealVuln repositories, the same
// binary with and without it: +3 labelled findings (a native query, an XPath
// evaluation, a deserialization), 7 matches reported on the statement's first
// line instead of its sink line and still matched, none lost; 54 unmatched
// added, all flows the engine already models reaching further -- servlet HTML
// assembled over many lines from values a request-derived call returned.

// javaStatementKinds are the statements whose lines are joined; a declaration
// is joined per declarator, as in JavaScript.
var javaStatementKinds = map[string]bool{
	"variable_declarator": true, "expression_statement": true,
	"return_statement": true, "throw_statement": true,
}

// javaBodyKinds hold statements of their own: a method or lambda body, an
// anonymous class, a switch.
var javaBodyKinds = map[string]bool{
	"block": true, "class_body": true, "constructor_body": true, "switch_block": true,
	"enum_body": true, "interface_body": true,
}

func javaTreeLines(content []byte, regions []lexctx.Region) ([]logicalLine, bool) {
	return treeJoinedLines("java", javaStatementKinds, javaBodyKinds, content, regions)
}
