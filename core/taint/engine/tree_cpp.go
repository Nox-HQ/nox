package engine

import "github.com/nox-hq/nox/core/lexctx"

// The tree-sitter front end for C and C++ (ADR 0006, rule 4), the Java one's
// technique (tree_java.go). Both are `;`-terminated, but the line segmenter
// reads a line as a statement unless a bracket is open, so an operator
// continued on the next line,
//
//	std::string q = std::string("SELECT * FROM users ") +
//	                "WHERE id = " + id;
//
// was two statements: q never read id.
//
// What the tree joins is the operator expression itself, a multi-line
// `binary_expression`, and nothing wider, as in Ruby (tree_ruby.go). Joining whole
// statements, as the Java front end does, was probed and rejected: a method
// chain
//
//	db->connection()
//	  ->sqlite3_exec("SELECT count(*) FROM t")
//	  ->label(id);
//
// became one statement that reads the tainted `id` and calls the sink with a
// constant, a flow the code does not have. A binary expression holds no call
// chain of its own, so it adds no such pair. A binary that holds a block or a
// closure keeps the line segmenter's handling, which follows its braces.
//
// One grammar, tree-sitter-cpp, parses both languages here: the line
// segmenter does not tell a `.c` from a `.cpp` file either (lexctx.LangCPP),
// and C++ is a superset for the statements joined. A C file the C++ grammar
// cannot parse is an error tree and falls back to the line segmenter.

var cppStatementKinds = map[string]bool{"binary_expression": true}

// cppBodyKinds hold statements of their own: a function, lambda or block
// body, a class or namespace body, a switch.
var cppBodyKinds = map[string]bool{
	"compound_statement": true, "field_declaration_list": true,
	"declaration_list": true, "enumerator_list": true,
}

func cppTreeLines(content []byte, regions []lexctx.Region) ([]logicalLine, bool) {
	return treeJoinedLines("cpp", cppStatementKinds, cppBodyKinds, content, regions)
}
