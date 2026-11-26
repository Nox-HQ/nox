package engine

import "github.com/nox-hq/nox/core/lexctx"

// The tree-sitter front end for PHP (ADR 0006, rule 4), the Java one's
// technique (tree_java.go): the PHP extractor follows function bodies by
// counting braces, and the tree supplies which physical lines are one
// statement. The shape it exists for is SQL built across lines,
//
//	$q = "SELECT * FROM users " .
//	     "WHERE id = " . $id;
//
// which the line segmenter read as two statements: no bracket is open at the
// end of the first, so $q never read $id.
//
// The `php` grammar, not `php_only`: a real file opens with `<?php` and may
// hold HTML around it, which `php_only` does not parse. A file of HTML
// templates is segmented through the same tree, its text nodes holding no
// statement.

// phpStatementKinds are the statements whose lines are joined.
var phpStatementKinds = map[string]bool{
	"expression_statement": true, "return_statement": true, "echo_statement": true,
}

// phpBodyKinds hold statements of their own: a function, method or closure
// body, a class body, a switch or match.
var phpBodyKinds = map[string]bool{
	"compound_statement": true, "declaration_list": true, "switch_block": true,
	"match_block": true, "enum_declaration_list": true,
}

func phpTreeLines(content []byte, regions []lexctx.Region) ([]logicalLine, bool) {
	return treeJoinedLines("php", phpStatementKinds, phpBodyKinds, content, regions)
}
