// SQL injection: a user id read from the environment is concatenated into a SQL
// string with snprintf and executed with mysql_query. Because the value is
// interpolated into the query text rather than bound as a parameter, a payload
// like `1 OR 1=1` alters the query. This is CWE-89. A correct scanner fires
// TAINT-001; the fix is a prepared statement (mysql_stmt_prepare + bind).
#include <stdlib.h>
#include <stdio.h>
#include <mysql/mysql.h>

void lookup_user(MYSQL *db) {
    char *id = getenv("USER_ID");
    char query[256];
    snprintf(query, sizeof(query), "SELECT * FROM users WHERE id = %s", id);
    mysql_query(db, query); // nox-expect: TAINT-001
}
