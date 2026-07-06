// Clean: placeholder / example credentials and constants — the kind of strings
// broad secret rules over-fire on. None of these are live secrets, and no
// untrusted value reaches a sink. A correct scanner emits nothing; any finding
// here is a false positive.

// Example values only — documented placeholders, not real credentials.
const EXAMPLE_API_KEY: &str = "your-api-key-here";
const EXAMPLE_TOKEN: &str = "xxxxxxxxxxxxxxxxxxxxxxxx";
const DATABASE_URL_TEMPLATE: &str = "postgres://USER:PASSWORD@localhost:5432/db";

// A UUID and a hex color — high-entropy-looking but plainly not secrets.
const REQUEST_ID: &str = "550e8400-e29b-41d4-a716-446655440000";
const BRAND_COLOR: &str = "#1a2b3c";

fn describe() -> String {
    // Constant, non-tainted SQL against a constant id: safe.
    let sql = "SELECT 1";
    format!("{} key={} token={}", sql, EXAMPLE_API_KEY, EXAMPLE_TOKEN)
}
