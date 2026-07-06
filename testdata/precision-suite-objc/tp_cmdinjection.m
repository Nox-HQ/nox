// Command injection: an attacker-controlled value (an environment variable
// standing in for any untrusted input) is formatted straight into a shell
// command and handed to the C system() call, which runs its argument via
// /bin/sh -c. This is CWE-78. A correct scanner fires TAINT-002. nox's
// Objective-C taint model sees the tainted value flow through -stringWithFormat:
// into the `system` sink with no allow-list.
#import <Foundation/Foundation.h>

void runReport(void) {
    NSString *name = [[[NSProcessInfo processInfo] environment] objectForKey:@"REPORT"];
    NSString *cmd = [NSString stringWithFormat:@"generate-report %@", name];
    system([cmd UTF8String]); // nox-expect: TAINT-002
}
