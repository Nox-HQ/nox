// Clean: the untrusted filename is reduced to its last path component before being
// joined under a fixed base directory, stripping any "../" traversal, so the file
// read cannot escape the intended directory. -lastPathComponent is a
// class-specific path-traversal sanitizer. A correct scanner emits nothing; any
// TAINT-004 finding here is a false positive.
#import <Foundation/Foundation.h>

NSString *readReportSafe(void) {
    NSString *fileName = [[[NSProcessInfo processInfo] environment] objectForKey:@"REPORT_FILE"];
    NSString *leaf = [fileName lastPathComponent];
    NSString *path = [NSString stringWithFormat:@"/var/reports/%@", leaf];
    return [NSString stringWithContentsOfFile:path encoding:NSUTF8StringEncoding error:nil];
}
