// Clean: the precision guardrail for extractor-parameter-as-source modeling.
// nox now seeds a web-framework EXTRACTOR parameter (web::Query<_>, web::Path<_>,
// web::Form<_>, web::Json<_>, and the bare axum forms) as tainted-on-entry. This
// handler takes ONLY ordinary typed parameters — an `i64` id, a borrowed
// `&Config` — neither of which is untrusted input, and drives sink-shaped calls
// (Command::new / std::fs::read) with values derived from them. A correct
// scanner emits nothing here: a plain typed parameter is NOT a source, only the
// specific extractor wrappers are. Any finding on this file is a false positive
// proving nox over-tainted a normal parameter.
use std::process::Command;
use std::fs;

struct Config {
    shell: String,
    root: String,
}

// build_report takes a trusted numeric id and a trusted config reference. The id
// is a value type coerced by the framework (not attacker-controlled text) and
// the config is internal state, so shelling out and reading a file with them is
// safe — no extractor type appears in the signature.
fn build_report(id: i64, cfg: &Config) {
    let out = Command::new(&cfg.shell)
        .arg("-c")
        .arg(format!("generate-report {}", id))
        .output();
    let _ = out;

    let path = format!("{}/report-{}.dat", cfg.root, id);
    let data = fs::read(path);
    let _ = data;
}
