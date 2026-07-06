// SQL injection: a user-controlled value is string-interpolated straight into a
// SQL string and handed to sqlite3_exec — no bound parameters. This is CWE-89.
// A correct scanner fires TAINT-001. nox's Swift taint model sees the tainted
// value reach the `\(...)` interpolation (CODE, per lexctx) that builds the query
// string and then the sqlite3_exec sink, with no sqlite3_bind sanitizer on the
// path.
import Foundation
import SQLite3

func lookupUser(_ db: OpaquePointer?) {
    let id = CommandLine.arguments[1]
    let sql = "SELECT * FROM users WHERE id = \(id)"
    sqlite3_exec(db, sql, nil, nil, nil) // nox-expect: TAINT-001
}
