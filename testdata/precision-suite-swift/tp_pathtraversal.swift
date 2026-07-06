// Path traversal: an attacker-controlled path is passed to String(contentsOfFile:)
// with no canonicalization or allow-base check, so `../../etc/passwd` escapes the
// intended directory. This is CWE-22. A correct scanner fires TAINT-004. nox's
// Swift taint model folds the discriminating `contentsOfFile:` label into the
// callee (String.contentsOfFile) so the file-reading initializer — and not a
// plain String(x) conversion — is the sink the tainted path reaches.
import Foundation

func readConfig() -> String {
    let path = CommandLine.arguments[1]
    let contents = (try? String(contentsOfFile: path, encoding: .utf8)) ?? "" // nox-expect: TAINT-004
    return contents
}
