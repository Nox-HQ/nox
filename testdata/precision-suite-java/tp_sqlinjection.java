// SQL injection: a request parameter is string-concatenated into a query
// executed via Statement.executeQuery — CWE-89. A correct scanner fires
// TAINT-001. The safe form (a PreparedStatement with a ? placeholder) lives in
// clean_safe_db.java.
package com.example.store;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;

public class UserStore {

    // lookupUser builds a query by concatenating untrusted input — the vulnerability.
    public ResultSet lookupUser(HttpServletRequest request, Statement stmt) throws SQLException {
        String id = request.getParameter("id");
        return stmt.executeQuery("SELECT name, email FROM users WHERE id = '" + id + "'"); // nox-expect: TAINT-001
    }
}
