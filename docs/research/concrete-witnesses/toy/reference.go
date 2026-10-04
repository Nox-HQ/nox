package toy

// Reference is written from the format description in token.go's package
// comment, without reading Validate. It shares no helper with it.
func Reference(s string) bool {
	const prefix = "acme_"
	if len(s) < len(prefix) || !equalFoldASCII(s[:len(prefix)], prefix) {
		return false
	}
	body := s[len(prefix):]
	if n := len(body); n >= 3 && body[n-3:] == ".v2" {
		body = body[:n-3]
	}
	if len(body) != 24 {
		return false
	}
	for i := 0; i < len(body); i++ {
		c := body[i]
		isLower := c >= 'a' && c <= 'z'
		isDigit := c >= '2' && c <= '7'
		if !isLower && !isDigit {
			return false
		}
	}
	return true
}

// equalFoldASCII is ABNF's case-insensitive string comparison (RFC 5234 §2.3),
// which folds only A-Z.
func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		x, y := a[i], b[i]
		if 'A' <= x && x <= 'Z' {
			x += 'a' - 'A'
		}
		if 'A' <= y && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}
