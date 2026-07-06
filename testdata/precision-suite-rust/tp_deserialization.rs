// Unsafe deserialization: attacker-controlled bytes are deserialized with
// bincode::deserialize into a rich type. Deserializing untrusted input is an
// RCE/DoS vector (CWE-502). A correct scanner fires TAINT-005.
use std::env;

fn load_session() {
    // The blob stands in for any untrusted byte source (a request body, a cookie).
    let blob = env::var("SESSION").unwrap_or_default();
    let session: Result<Session, _> = bincode::deserialize(blob.as_bytes()); // nox-expect: TAINT-005
    let _ = session;
}

struct Session {
    _user: String,
}
