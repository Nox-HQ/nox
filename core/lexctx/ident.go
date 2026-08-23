package lexctx

// asciiIdentStart reports whether b can begin an ASCII identifier: a letter or
// underscore. Every language scanner had a byte-identical copy of this; the
// per-language predicates now delegate here, with any language-specific extra
// (Dart's `$`) composed on top.
func asciiIdentStart(b byte) bool {
	return b == '_' || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// asciiIdentPart reports whether b can appear inside an ASCII identifier: an
// identifier-start byte or a digit.
func asciiIdentPart(b byte) bool {
	return asciiIdentStart(b) || (b >= '0' && b <= '9')
}
