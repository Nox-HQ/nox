// SQL injection: a user-controlled value is format!-interpolated straight into
// a SQL string and handed to sqlx::query — no bind parameters. This is CWE-89.
// A correct scanner fires TAINT-001. nox's Rust taint model sees the tainted
// value reach the format! (tainting the query string) and then the sqlx::query
// sink, with no `.bind()` sanitizer on the path.
use std::env;

async fn lookup_user(pool: &sqlx::PgPool) {
    let id = env::var("USER_ID").unwrap_or_default();
    let sql = format!("SELECT * FROM users WHERE id = {}", id);
    let rows = sqlx::query(&sql).fetch_all(pool).await; // nox-expect: TAINT-001
    let _ = rows;
}
