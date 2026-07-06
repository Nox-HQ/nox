// Clean: the user id is bound as a PARAMETER via a prepared statement rather than
// concatenated into the SQL text. mysql_stmt_bind_param keeps the value out of
// the query string, so no SQL injection is possible. A correct scanner emits
// nothing; a TAINT-001 finding here is a false positive. mysql_query is called
// only with a constant DDL string, which carries no taint.
#include <stdlib.h>
#include <string.h>
#include <mysql/mysql.h>

void lookup_user(MYSQL *db, MYSQL_STMT *stmt) {
    char *id = getenv("USER_ID");
    // Prepared statement with a bound parameter — value never enters SQL text.
    mysql_stmt_prepare(stmt, "SELECT * FROM users WHERE id = ?", 32);
    MYSQL_BIND bind;
    memset(&bind, 0, sizeof(bind));
    bind.buffer = id;
    mysql_stmt_bind_param(stmt, &bind);
    mysql_stmt_execute(stmt);

    // A constant schema query carries no untrusted input.
    mysql_query(db, "SELECT VERSION()");
}
