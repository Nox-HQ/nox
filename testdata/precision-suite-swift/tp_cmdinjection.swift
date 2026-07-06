// Command injection: an attacker-controlled value (an environment variable
// standing in for any untrusted input) is string-interpolated straight into a
// shell command and handed to the C `system()` call, which runs its argument via
// /bin/sh -c. This is CWE-78. A correct scanner fires TAINT-002. nox's Swift
// taint model sees the tainted value reach the `\(...)` interpolation (which
// lexctx classifies as CODE) and then the `system` sink with no allow-list.
import Foundation

func runReport() {
    let name = ProcessInfo.processInfo.environment["REPORT"] ?? ""
    system("generate-report \(name)") // nox-expect: TAINT-002
}
