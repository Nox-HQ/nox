// Clean: parameterized SQL via sqlx bind parameters. The user-controlled value
// is passed to `.bind()` — sent to the driver as data, never concatenated into
// the query string — so there is NO SQL injection here. A correct scanner emits
// nothing; any TAINT-001 finding on this file is a false positive.
use std::env;

async fn lookup_user(pool: &sqlx::PgPool) {
    let id = env::var("USER_ID").unwrap_or_default();
    // Placeholder $1 + .bind() is the parameterized, safe form.
    let rows = sqlx::query("SELECT * FROM users WHERE id = $1")
        .bind(id)
        .fetch_all(pool)
        .await;
    let _ = rows;
}
