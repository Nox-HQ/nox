package engine

import "github.com/nox-hq/nox/core/lexctx"

// The tree-sitter front end for Ruby (ADR 0006, rule 4), narrower than the
// other languages'. Ruby statements end at the newline, so the line segmenter
// joins a line to the next only inside an open bracket, and a bracketless
// call whose argument is built with an operator across lines became several
// statements:
//
//	User.find_by_sql "select * from users where a = 'x' AND " +
//	  "b = #{params[:unsafe]}"
//
// What the tree joins is therefore the operator expression itself, a
// multi-line `binary` or `chained_string`, and nothing wider. Joining whole
// statements, as the Java front end does, was measured and rejected: on a
// multi-line method chain
//
//	@articles = Article
//	  .published
//	  .order(Arel.sql("articles.published_at DESC"))
//	  .where(user_id: ids)
//
// one statement read the tainted `ids` and called the `Arel.sql` sink, which
// the line segmenter, reading the calls one per line, kept apart. Over forem and
// mastodon that added 20 false positives for one true positive and moved 32
// findings to the first line of their chain. A binary expression holds no call
// chain of its own, so it adds no such pair.
// A binary that holds a block or a keyword body keeps the line segmenter's
// handling, which follows its `end`.

var rubyStatementKinds = map[string]bool{
	"binary": true, "chained_string": true,
}

// rubyBodyKinds hold statements of their own: a block, a lambda, a method or
// class body, a conditional or loop, a begin block.
var rubyBodyKinds = map[string]bool{
	"do_block": true, "block": true, "lambda": true, "body_statement": true,
	"method": true, "singleton_method": true, "class": true, "module": true,
	"begin": true, "if": true, "unless": true, "case": true, "while": true,
	"until": true, "for": true, "then": true, "else": true, "do": true,
}

func rubyTreeLines(content []byte, regions []lexctx.Region) ([]logicalLine, bool) {
	return treeJoinedLines("ruby", rubyStatementKinds, rubyBodyKinds, content, regions)
}
