// SQL injection: a request parameter is string-concatenated into a JDBC query
// executed via Statement.executeQuery — CWE-89. A correct scanner fires
// TAINT-001. The tainted value is built into the SQL text rather than bound as a
// parameter on a PreparedStatement, which is the dangerous, injectable form.
package repositories

import java.sql.Statement

class UserRepository {
  // lookup composes the query by concatenating untrusted input — the bug.
  def lookup(request: Request, stmt: Statement): Unit = {
    val id = request.getQueryString("id")
    val sqlText = "SELECT name, email FROM users WHERE id = '" + id + "'"
    stmt.executeQuery(sqlText) // nox-expect: TAINT-001
  }
}
