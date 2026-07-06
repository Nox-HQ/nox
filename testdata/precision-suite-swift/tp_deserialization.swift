// Unsafe deserialization: attacker-controlled bytes (derived from a process
// argument) are handed to the legacy, non-secure
// NSKeyedUnarchiver.unarchiveObject(with:), which will instantiate any archived
// class — a well-known RCE vector. This is CWE-502. A correct scanner fires
// TAINT-005. nox's Swift taint model folds the `with:` label
// (unarchiveObject.with) and matches the tainted Data reaching it; the secure
// NSSecureCoding form (unarchivedObject(ofClass:from:)) is the safe path.
//
// The unarchiver is referenced through an idiomatic `typealias` — identical
// behavior to spelling NSKeyedUnarchiver at the call site, and the form real
// codebases use to abbreviate long Foundation type names.
import Foundation

typealias Archiver = NSKeyedUnarchiver

func loadState() -> Any? {
    let arg = CommandLine.arguments[1]
    let raw = Data(base64Encoded: arg) ?? Data()
    let obj = Archiver.unarchiveObject(with: raw) // nox-expect: TAINT-005
    return obj
}
