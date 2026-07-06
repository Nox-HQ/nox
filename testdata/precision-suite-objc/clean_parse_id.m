// Clean: numeric coercion sanitizes the untrusted value before it reaches a shell
// command. -[NSString integerValue] parses the leading integer and yields 0 on
// non-numeric input, so no shell metacharacter can survive into the command. A
// correct scanner emits nothing; any TAINT-002 finding here is a false positive.
#import <Foundation/Foundation.h>

void purgeRecord(void) {
    NSString *raw = [[[NSProcessInfo processInfo] environment] objectForKey:@"RECORD_ID"];
    NSInteger recordId = [raw integerValue];
    NSString *cmd = [NSString stringWithFormat:@"purge --id %ld", (long)recordId];
    system([cmd UTF8String]);
}
