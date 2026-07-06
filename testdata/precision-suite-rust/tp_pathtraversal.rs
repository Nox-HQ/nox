// Path traversal: a user-controlled path is passed straight to std::fs::read
// with no canonicalization or file_name() component-stripping, so `../../etc/
// passwd` escapes the intended directory. This is CWE-22. A correct scanner
// fires TAINT-004.
use std::env;
use std::fs;

fn serve_file() -> Vec<u8> {
    let user_path = env::var("FILE").unwrap_or_default();
    let data = fs::read(user_path).unwrap_or_default(); // nox-expect: TAINT-004
    data
}
