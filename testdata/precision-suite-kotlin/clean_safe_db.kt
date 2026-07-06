// Clean: parameterized SQL via a PreparedStatement with a `?` placeholder. The
// user-controlled value is bound with setString — sent to the driver as data,
// never concatenated into the query string — so there is NO SQL injection here.
// A correct scanner emits nothing; any TAINT-001 finding on this file is a false
// positive.
package com.example

import java.sql.Connection
import javax.servlet.http.HttpServletRequest

class UserStore {
    fun lookup(request: HttpServletRequest, conn: Connection) {
        val id = request.getParameter("id")
        val stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?")
        stmt.setString(1, id)
        val rows = stmt.executeQuery()
    }
}
