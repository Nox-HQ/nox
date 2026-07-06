// Command injection: an attacker-controlled value (an environment variable
// standing in for any untrusted input) flows into a shell invocation via
// Command::new("sh").arg("-c", ...) with no allow-list. This is CWE-78. A
// correct scanner fires TAINT-002. nox's Rust taint model matches the tainted
// value flowing through `.arg` into the std::process::Command builder.
use std::env;
use std::process::Command;

// run_report shells out with a user-supplied report name — the vulnerability.
fn run_report() {
    let name = env::var("REPORT").unwrap_or_default();
    let out = Command::new("sh")
        .arg("-c")
        .arg(format!("generate-report {}", name)) // nox-expect: TAINT-002
        .output();
    let _ = out;
}
