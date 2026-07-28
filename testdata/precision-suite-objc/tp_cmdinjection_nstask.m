// Command injection via NSTask — a LABELED FALSE NEGATIVE nox's Objective-C model
// does not catch. It is kept in the corpus, not deleted: inflating recall by
// removing a hard true positive would defeat the point of an honest measurement
// suite.
//
// The idiom is the idiomatic Foundation NSTask form where the tainted value is
// assigned into the `arguments` PROPERTY (an array built from the untrusted
// string) and the shell is launched by a later bare `[task launch]` with no
// argument. This is a genuine CWE-78 command injection (a correct scanner fires
// TAINT-002 on the launch), but nox's Objective-C extractor is a line/statement
// recognizer: it tracks taint through assignments whose LHS is a BARE identifier,
// so an assignment to a member PROPERTY (`task.arguments = …`) is not modeled as
// a distinct binding, the tainted array never associates with `task`, and
// `[task launch]` carries no argument to match. Closing it needs field/receiver
// taint tracking — future work, not a curation trick.
#import <Foundation/Foundation.h>

void runTask(void) {
    NSString *arg = [[[NSProcessInfo processInfo] environment] objectForKey:@"ARG"];
    NSTask *task = [[NSTask alloc] init];
    task.launchPath = @"/bin/sh";
    task.arguments = @[@"-c", arg];
    [task launch]; // nox-expect: TAINT-002
}
