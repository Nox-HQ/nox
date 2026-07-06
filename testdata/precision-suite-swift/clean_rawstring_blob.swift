// Clean: a base64 data-URI image embedded in a raw string literal (#"..."#) — the
// single most common secret/pattern false-positive carrier. lexctx classifies the
// whole raw string as a data blob, so pattern matches inside it are suppressed,
// and there is no taint flow. A correct scanner emits nothing; any finding here is
// a false positive.
import Foundation

// A raw string carries the blob verbatim (no escaping), spanning as one string.
let logoPNG = #"data:image/png;base64,iVBORw0KGgoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"#

// A raw #"..."# form of a short opaque token — still data, not a live secret.
let signature = #"AKIAIOSFODNN7EXAMPLEKEYNOTREAL0000"#

func logo() -> String {
    return logoPNG
}
