package engine

import (
	"github.com/nox-hq/nox/core/lexctx"
	"github.com/nox-hq/nox/core/treesitter"
)

// The tree-sitter front end for C++ (ADR 0006, rule 4), for .cpp, .cc and
// .cxx files; headers keep the line segmenter. It joins what the C front end
// joins (tree_c.go) -- a declarator, an expression statement, a return --
// and a multi-line binary expression, with the C front end's local use of an
// error tree (16.7% of the corpus's C++ files have an error somewhere).
//
// C++ has method chains, and a chain read as one statement is the false
// positive that narrowed Ruby, Scala, Swift and Rust to binary expressions:
//
//	auto r = db
//	    .exec("SELECT 1")
//	    .bind(id);
//
// calls the sink with a constant and reads the tainted id in one statement.
// So a statement holding a chained call, a call made on the result of a call
// (`a.f().g()`, `p->f()->g()`), keeps the line segmenter's handling, as one
// holding a block (a lambda's body among them) does; reading a member of a
// call's result (`make().prefix`) is not a chain. A binary expression inside
// such a statement is still joined when it holds no chain itself.

var cppStatementKinds = map[string]bool{
	"init_declarator": true, "expression_statement": true, "return_statement": true,
	"binary_expression": true,
}

var cppBodyKinds = map[string]bool{
	"compound_statement": true, "initializer_list": true,
	"field_declaration_list": true, "enumerator_list": true,
	"declaration_list": true,
}

// cppChainedCall reports whether node i is the member access of a chained
// call: a field_expression that is a call's function and whose object is
// itself a call. Its object is its first child.
func cppChainedCall(tree *treesitter.Tree, i int) bool {
	n := tree.Nodes[i]
	if n.Kind != "field_expression" || n.Field != "function" || i+1 >= len(tree.Nodes) {
		return false
	}
	obj := tree.Nodes[i+1]
	return int(obj.Parent) == i && obj.Field == "argument" && obj.Kind == "call_expression"
}

func cppTreeLines(content []byte, regions []lexctx.Region) ([]logicalLine, bool) {
	return treeJoinedLinesBlocked("cpp", cppStatementKinds, cppBodyKinds, cppChainedCall, content, regions, true)
}
