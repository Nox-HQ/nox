// LABELED FALSE NEGATIVE (kept honest, not deleted): a genuine command-injection
// bug nox's Swift model does NOT catch. It is the idiomatic Foundation Process
// form where the tainted value is assigned into the `task.arguments` PROPERTY (an
// array literal built with `\(name)` interpolation) and the shell is invoked by a
// later bare `task.launch()` with no argument. This is CWE-78 and a correct
// scanner fires TAINT-002.
//
// nox's Swift extractor is a line/statement RECOGNIZER (only Go gets go/ast). It
// tracks taint through assignments whose LHS is a bare identifier; an assignment
// to a member PROPERTY (`task.arguments = ...`) is not modeled as a distinct
// binding, so the tainted array never associates with `task`, and `task.launch()`
// carries no argument to match. Closing it needs field/receiver taint tracking —
// future work, not a curation trick. Removing this hard TP to inflate recall
// would defeat the point of an honest measurement suite.
import Foundation

func runReport() {
    let name = ProcessInfo.processInfo.environment["REPORT"] ?? ""
    let task = Process()
    task.launchPath = "/bin/sh"
    task.arguments = ["-c", "generate-report \(name)"]
    task.launch() // nox-expect: TAINT-002
}
