// Command injection via a web-framework EXTRACTOR parameter — a TRUE POSITIVE
// nox's Rust model now catches (previously the suite's honest false negative).
//
// This is a real, idiomatic actix-web handler: the untrusted input arrives as a
// `web::Query<Params>` PARAMETER, not as a source CALL. nox's taint model
// introduces taint from source CALLS and attribute chains; on top of that, the
// Rust extractor (core/taint/engine/extract_rust.go) now seeds a parameter whose
// TYPE is a web extractor (web::Query/Form/Json/Path, or the bare axum forms) as
// tainted-on-entry via a synthetic `binding = <source>()` statement. So
// `query.cmd` here IS marked tainted, and the Command::new(...).arg(...) sink
// below fires TAINT-002 — matching a correct scanner.
//
// Only these specific extractor wrappers seed taint; a plain typed parameter
// (`id: i64`, `cfg: &Config`) never does — see clean_typed_param.rs, the
// precision guardrail proving normal parameters are not over-tainted.
use actix_web::web;
use std::process::Command;

struct Params {
    cmd: String,
}

async fn run(query: web::Query<Params>) {
    let out = Command::new("sh")
        .arg("-c")
        .arg(&query.cmd) // nox-expect: TAINT-002
        .output();
    let _ = out;
}
