// Clean: the user-controlled value is coerced to a typed integer with
// str::parse::<i64>() before being interpolated into SQL. Numeric coercion
// removes every injection metacharacter, so no SQLi is possible even though a
// format! builds the query. A correct scanner emits nothing; a TAINT-001
// finding here is a false positive.
use std::env;

async fn lookup_by_id(pool: &sqlx::PgPool) {
    let raw = env::var("USER_ID").unwrap_or_default();
    let id: i64 = raw.parse().unwrap_or(0);
    // `id` is an i64 — it cannot carry a SQL payload.
    let sql = format!("SELECT * FROM users WHERE id = {}", id);
    let rows = sqlx::query(&sql).fetch_all(pool).await;
    let _ = rows;
}
