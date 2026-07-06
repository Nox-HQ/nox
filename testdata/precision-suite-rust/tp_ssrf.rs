// SSRF: a user-controlled URL is fetched directly with reqwest::get, letting an
// attacker point the server at internal metadata endpoints (169.254.169.254) or
// intranet hosts. This is CWE-918. A correct scanner fires TAINT-006.
use std::env;

async fn fetch_avatar() {
    let user_url = env::var("AVATAR_URL").unwrap_or_default();
    let resp = reqwest::get(&user_url).await; // nox-expect: TAINT-006
    let _ = resp;
}
