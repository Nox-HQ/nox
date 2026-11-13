// Package textual decides whether file content is text, which every
// line-oriented reader in nox (rules, waivers) needs to agree on.
package textual

import "bytes"

// sniffLen is how much of the head is examined.
const sniffLen = 512

// IsBinary reports whether content is binary: a NUL byte in its first 512
// bytes. Source, configuration and lockfiles never contain one; compiled
// executables and most binary formats do, near the start. Rules skip such
// content because a binary embeds pattern text it does not "contain" (nox
// itself embeds every rule's remediation), and waivers skip it because a
// binary holds no comments.
func IsBinary(content []byte) bool {
	head := content
	if len(head) > sniffLen {
		head = head[:sniffLen]
	}
	return bytes.IndexByte(head, 0) >= 0
}
