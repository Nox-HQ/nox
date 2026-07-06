// Clean: numeric coercion with String.toInteger() removes every injection
// metacharacter before the value is used, so the concatenated query and the
// command are safe. A correct scanner emits nothing; any finding is a false
// positive.
package com.example

import groovy.sql.Sql

class SafeStore {
    def lookup(request, Sql sql) {
        def raw = request.getParameter("id")
        def id = raw.toInteger() // numeric — no metacharacters survive
        def query = "SELECT * FROM users WHERE id = " + id
        return sql.rows(query)
    }

    def runReport(request) {
        def rawCount = request.getParameter("count")
        def n = rawCount.toInteger() // numeric coercion clears the injection classes
        "make-report --count ${n}".execute() // n is an int; nothing to inject
    }
}
