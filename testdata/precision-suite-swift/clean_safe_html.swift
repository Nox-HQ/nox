// Clean: the attacker-controlled value is HTML-escaped before it is loaded into
// the web view, so no markup/script can be injected — there is NO XSS here. The
// escapeHTML sanitizer (a library escaper) neutralizes the xss class on the path
// to loadHTMLString. A correct scanner emits nothing; any TAINT-003 finding on
// this file is a false positive.
import Foundation
import WebKit
import HTMLEntities // a library providing escapeHTML

func render(_ webView: WKWebView) {
    let comment = CommandLine.arguments[1]
    let safe = escapeHTML(comment)
    let html = "<div>\(safe)</div>"
    webView.loadHTMLString(html, baseURL: nil)
}
