// Clean: a base64 data-URI blob embedded in an @"..." NSString literal, plus an
// opaque token constant. These are DATA, not code — the lexctx classifier marks
// the NSString body as a string region and the taint engine never treats a string
// literal as a tainted source or a sink argument. A broad text-matching rule might
// trip on the `system` substring or the base64 payload; a correct taint scanner
// emits nothing. Any finding here is a false positive.
#import <Foundation/Foundation.h>

NSString *iconDataURI(void) {
    // A long base64 data-URI — a data blob, never executable code.
    return @"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAC0lEQVR42mNksystems/dQAAAABJRU5ErkJggg==";
}

NSString *opaqueToken(void) {
    // A fixed opaque identifier that merely looks secret-ish; no untrusted input.
    return @"a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";
}
