// Command injection via a web-framework EXTRACTOR parameter — an HONEST FALSE
// NEGATIVE nox's Rust model does not catch (recall gap, documented in README).
//
// This is a real, idiomatic actix-web handler: the untrusted input arrives as a
// destructured `web::Query(params)` PARAMETER, not as a source CALL. nox's taint
// model (Python/JS/Go/Rust alike) introduces taint from source CALLS and
// attribute chains, never from a function parameter's TYPE — so `params.cmd`
// here is never marked tainted, and the Command::new(...).arg(...) sink below
// does not fire. A correct scanner SHOULD fire TAINT-002; nox misses it.
//
// It is kept in the corpus as a labeled FN (not deleted to inflate recall): the
// annotation scores as a false negative, which is exactly the honest signal the
// suite exists to surface. Closing it needs parameter-as-source modeling for
// web extractors — future work, not a curation trick.
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
