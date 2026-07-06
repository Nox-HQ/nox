// SSRF: an attacker-controlled URL string is turned into an NSURL and fetched by
// an NSURLSession data task with no host allow-list, so the server can be coerced
// into requesting an internal address. This is CWE-918. A correct scanner fires
// TAINT-006. nox folds the message-send selector (dataTaskWithURL) and matches
// the tainted URL flowing into it.
#import <Foundation/Foundation.h>

void fetch(NSURLSession *session) {
    NSString *raw = [[NSUserDefaults standardUserDefaults] stringForKey:@"endpoint"];
    NSURL *url = [NSURL URLWithString:raw];
    NSURLSessionDataTask *task = [session dataTaskWithURL:url]; // nox-expect: TAINT-006
    [task resume];
}
