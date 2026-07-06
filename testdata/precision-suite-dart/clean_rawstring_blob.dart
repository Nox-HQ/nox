// Clean: a long base64 `data:` URI embedded in a Dart RAW string (`r'...'`), plus
// an opaque raw-string token. Raw strings process no escapes and no
// interpolation, so lexctx classifies the whole body as a data blob — the class
// that produces the overwhelming majority of pattern false positives (a 32-char
// alphanumeric run inside an embedded base64 SVG). There is no taint flow and no
// sink here. A correct scanner emits nothing; any finding is a false positive.
class Assets {
  // A base64 data-URI blob (icon) — data, not a credential, and never a sink arg.
  static const icon =
      r'data:image/svg+xml;base64,AKIA1234567890ABCDEF1234567890ABAKIA1234567890ABCDEF1234567890AB==';

  // A raw-string regex with `$` and `\` bytes that are literal (no interpolation).
  static final idPattern = RegExp(r'^user_\$[0-9A-F]{16}$');
}
