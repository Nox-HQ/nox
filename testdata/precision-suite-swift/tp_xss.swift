// XSS via WKWebView: an un-escaped attacker-controlled string is loaded straight
// into a web view with loadHTMLString, so any embedded markup/script executes in
// the web view's context. This is CWE-79. A correct scanner fires TAINT-003.
// nox's Swift taint model matches the tainted value flowing into loadHTMLString
// with no HTML-escape sanitizer on the path.
import Foundation
import WebKit

func render(_ webView: WKWebView) {
    let comment = CommandLine.arguments[1]
    let html = "<div>\(comment)</div>"
    webView.loadHTMLString(html, baseURL: nil) // nox-expect: TAINT-003
}
