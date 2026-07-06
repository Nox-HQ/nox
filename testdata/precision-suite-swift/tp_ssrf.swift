// SSRF: an attacker-controlled URL string is turned into a URL and fetched by a
// URLSession data task with no host allow-list, so the server can be coerced into
// requesting an internal address. This is CWE-918. A correct scanner fires
// TAINT-006. nox's Swift taint model folds the `with:` label
// (session.dataTask.with) and matches the tainted URL flowing into it.
import Foundation

func fetch(_ session: URLSession) {
    let raw = CommandLine.arguments[1]
    let url = URL(string: raw)!
    let task = session.dataTask(with: url) // nox-expect: TAINT-006
    task.resume()
}
