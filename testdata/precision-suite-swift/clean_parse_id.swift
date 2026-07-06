// Clean: numeric coercion sanitizes the tainted value before it reaches a sink.
// `Int(raw)` returns nil on any non-numeric input, so a path/command
// metacharacter can never survive — the value handed onward is a validated
// integer. A correct scanner emits nothing; any finding here is a false positive.
import Foundation

func openRecord() -> String {
    let raw = CommandLine.arguments[1]
    // Int(...) coercion strips every injection metacharacter (nil otherwise).
    guard let n = Int(raw) else { return "" }
    let path = "/var/records/\(n).txt"
    return (try? String(contentsOfFile: path, encoding: .utf8)) ?? ""
}
