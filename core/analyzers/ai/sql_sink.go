package ai

import (
	"regexp"

	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/lexctx"
)

// sqlStatementRE recognises the opening of a SQL statement. The keyword pair is
// required (`INSERT INTO`, not a bare `INSERT`) so an English sentence
// containing "select" or "update" is not mistaken for SQL.
var sqlStatementRE = regexp.MustCompile(`(?i)\b(?:SELECT\s+[\w*` + "`" + `"\[]|INSERT\s+INTO|INSERT\s+OR\s+\w+\s+INTO|REPLACE\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM|CREATE\s+(?:TABLE|INDEX|VIEW)|ALTER\s+TABLE|DROP\s+TABLE|UPSERT\s+INTO|WITH\s+\w+\s+AS\s*\()`)

// isSQLStatementExec reports whether an AI-049 match is a database call
// executing a SQL statement rather than a code-evaluation sink.
//
// AI-049 is "AI output passed to eval/exec function", CWE-95 (eval injection).
// It separates a real eval sink from a database call by requiring an
// AI-vocabulary token (`prompt`, `completion`, `model_output`, …) among the call
// arguments. That gate fails when the token is a COLUMN NAME inside the SQL
// text:
//
//	r.db.Exec(`INSERT INTO schedules (id, prompt) VALUES (?, ?)`, 1, "x")
//
// which is placeholder-parameterised SQL — the safe form — carrying no
// AI-derived value at all. `database/sql`'s Exec and DB-API's execute evaluate
// SQL, not code, so CWE-95 cannot apply to them whatever the arguments are, and
// the finding is categorically wrong rather than merely low-value. It is
// therefore dropped, following IAC-193.
//
// The discriminator is the SQL text, not the receiver name. `db.Exec(model_output)`
// — a model emitting raw SQL that is then executed — carries no SQL literal at
// the call site and still fires, as it should. AI content interpolated into
// exec'd code (`exec(f"run({prompt})")`) is likewise untouched: it has no SQL
// statement in it.
func isSQLStatementExec(content []byte, f *findings.Finding) bool {
	start := lexctx.LineColToOffset(content, f.Location.StartLine, f.Location.StartColumn)
	end := lexctx.LineColToOffset(content, f.Location.EndLine, f.Location.EndColumn)
	if end <= start || end > len(content) {
		return false
	}
	return sqlStatementRE.Match(content[start:end])
}
