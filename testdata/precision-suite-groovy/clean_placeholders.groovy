// Clean: parameterized SQL via a groovy.sql.Sql placeholder query. The
// user-controlled value is passed as a bind parameter in the 2nd positional
// argument (the value list) — sent to the driver as data, never concatenated into
// the query string — so there is NO SQL injection here. A correct scanner emits
// nothing; any TAINT-001 finding on this file is a false positive.
package com.example

import groovy.sql.Sql

class UserStore {
    def lookup(request, Sql sql) {
        def id = request.getParameter("id")
        // The `?` placeholder is bound from the value list; `id` is data, not SQL.
        return sql.rows("SELECT * FROM users WHERE id = ?", [id])
    }
}
