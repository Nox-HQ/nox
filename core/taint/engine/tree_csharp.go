package engine

import "github.com/nox-hq/nox/core/lexctx"

// The tree-sitter front end for C# (ADR 0006, rule 4), the Java one's
// technique (tree_java.go): the C# extractor follows method bodies by counting
// braces, and the tree supplies which physical lines are one statement. The
// shape it exists for is SQL built across lines,
//
//	string q = "SELECT * FROM users " +
//	           "WHERE id = " + id;
//
// which the line segmenter read as two statements: no bracket is open at the
// end of the first, so q never read id.

// csharpStatementKinds are the statements whose lines are joined; a declaration
// is joined per declarator, as in Java.
var csharpStatementKinds = map[string]bool{
	"variable_declarator": true, "expression_statement": true,
	"return_statement": true, "throw_statement": true,
}

// csharpBodyKinds hold statements of their own: a method, lambda or accessor
// body, a type body, a switch.
var csharpBodyKinds = map[string]bool{
	"block": true, "declaration_list": true, "switch_body": true,
	"enum_member_declaration_list": true, "accessor_list": true,
}

func csharpTreeLines(content []byte, regions []lexctx.Region) ([]logicalLine, bool) {
	return treeJoinedLines("csharp", csharpStatementKinds, csharpBodyKinds, content, regions)
}
