// Unsafe deserialization: attacker-controlled bytes are handed to the legacy
// +[NSKeyedUnarchiver unarchiveObjectWithData:] which does NON-secure unarchiving
// — it will instantiate whatever classes the archive names, an RCE vector. This
// is CWE-502. A correct scanner fires TAINT-005. The safe path is the
// NSSecureCoding form (unarchivedObjectOfClass:fromData:error: requiring secure
// coding). nox folds the selector and sees the tainted data reach the sink.
#import <Foundation/Foundation.h>

id loadState(void) {
    NSString *b64 = [[NSUserDefaults standardUserDefaults] stringForKey:@"state"];
    NSData *data = [[NSData alloc] initWithBase64EncodedString:b64 options:0];
    return [NSKeyedUnarchiver unarchiveObjectWithData:data]; // nox-expect: TAINT-005
}
