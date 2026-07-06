// SQL injection: a user-controlled request parameter is string-concatenated into a
// SQL query and run with groovy.sql.Sql.rows — no placeholder, no bind parameters.
// This is CWE-89. A correct scanner fires TAINT-001. nox sees `id` tainted by
// request.getParameter reach the .rows sink; because the tainted value is in the
// query STRING (1st positional argument) rather than a bind-parameter list, the
// parameterized-query exemption does not apply and the finding fires.
package com.example

import groovy.sql.Sql

class UserStore {
    def lookup(request, Sql sql) {
        def id = request.getParameter("id")
        def query = "SELECT * FROM users WHERE id = '" + id + "'"
        return sql.rows(query) // nox-expect: TAINT-001
    }
}
