// Clean: the untrusted comment is HTML-escaped before it is placed into the markup
// loaded by the web view, so no attacker markup can be reflected. -escapeHTML is a
// class-specific XSS sanitizer. A correct scanner emits nothing; any TAINT-003
// finding here is a false positive.
#import <Foundation/Foundation.h>
#import <WebKit/WebKit.h>

void renderSafe(WKWebView *webView) {
    NSString *comment = [[[NSProcessInfo processInfo] environment] objectForKey:@"COMMENT"];
    NSString *safe = [comment escapeHTML];
    NSString *html = [NSString stringWithFormat:@"<div>%@</div>", safe];
    [webView loadHTMLString:html baseURL:nil];
}
