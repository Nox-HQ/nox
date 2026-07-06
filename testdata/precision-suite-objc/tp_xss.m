// XSS (WebView): an attacker-controlled comment is interpolated into an HTML
// string and loaded into a web view with -loadHTMLString:baseURL: without being
// escaped, so the markup is reflected and executed. This is CWE-79. A correct
// scanner fires TAINT-003. The safe form HTML-escapes the value first (see
// clean_safe_html.m). nox folds the selector and sees the tainted HTML reach the
// loadHTMLString sink.
#import <Foundation/Foundation.h>
#import <WebKit/WebKit.h>

void render(WKWebView *webView) {
    NSString *comment = [[[NSProcessInfo processInfo] environment] objectForKey:@"COMMENT"];
    NSString *html = [NSString stringWithFormat:@"<div>%@</div>", comment];
    [webView loadHTMLString:html baseURL:nil]; // nox-expect: TAINT-003
}
