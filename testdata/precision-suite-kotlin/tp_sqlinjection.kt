// SQL injection: a user-controlled request parameter is string-concatenated into
// a SQL query and executed with Statement.executeQuery — no PreparedStatement,
// no bind parameters. This is CWE-89. A correct scanner fires TAINT-001. nox's
// Kotlin taint model sees `id` tainted by request.getParameter reach the
// .executeQuery sink with no prepareStatement sanitizer on the path.
package com.example

import java.sql.Statement
import javax.servlet.http.HttpServletRequest

class UserStore {
    fun lookup(request: HttpServletRequest, stmt: Statement) {
        val id = request.getParameter("id")
        val sql = "SELECT * FROM users WHERE id = '" + id + "'"
        val rows = stmt.executeQuery(sql) // nox-expect: TAINT-001
    }
}
