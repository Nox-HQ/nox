// Path traversal: an attacker-controlled filename is used to build a path that is
// read by +[NSString stringWithContentsOfFile:...] with no allow-base check, so
// an attacker can escape the intended directory ("../../etc/passwd"). This is
// CWE-22. A correct scanner fires TAINT-004. The safe form validates the
// lastPathComponent against an allow-base (see clean_safe_path.m). nox folds the
// message-send selector and sees the tainted path reach the file-read sink.
#import <Foundation/Foundation.h>

NSString *readReport(void) {
    NSString *fileName = [[[NSProcessInfo processInfo] environment] objectForKey:@"REPORT_FILE"];
    NSString *path = [NSString stringWithFormat:@"/var/reports/%@", fileName];
    return [NSString stringWithContentsOfFile:path encoding:NSUTF8StringEncoding error:nil]; // nox-expect: TAINT-004
}
