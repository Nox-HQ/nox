// A base64 data: URI embedded in a Go raw string (backticks). The decoded body
// contains long alphanumeric runs and AKIA-looking substrings — the classic
// secrets false-positive class. The lexctx-Go blob gating plus the secrets
// decode-path markup suppression must keep this clean: zero findings.
package assets

// Icon is a 1x1 transparent PNG plus a decorative SVG, inlined as a data URI.
const Icon = `data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciPjxwYXRoIGQ9Ik0xMiAyQzYuNDggMiAyIDYuNDggMiAxMnM0LjQ4IDEwIDEwIDEwQUtJQUlPU0ZPRE5ON0VYQU1QTEVhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejAxMjM0NTY3ODlBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWiIvPjwvc3ZnPg==`
