package secrets

import (
	"bytes"

	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/lexctx"
)

// dataURIMarker is the boundary between a data: URI's declaration and its
// encoded payload. Everything after it, up to the closing quote or whitespace,
// is encoded binary.
var dataURIMarker = []byte(";base64,")

// dataURIScheme anchors the marker to an actual data: URI rather than any
// stray ";base64," in prose.
var dataURIScheme = []byte("data:")

// inDataURIPayload reports whether a finding's matched span falls inside the
// payload of a `data:<mime>;base64,…` URI.
//
// Such a payload is encoded binary. The long mixed-case alphanumeric runs
// inside it match the character-class-and-length patterns many vendor secret
// rules use, but they are never credentials — a real secret smuggled through
// base64 is caught by DecodeAndScan, which scans the decoded bytes.
//
// inEmbeddedBlob covers the same class but consults lexctx, which returns
// LangUnknown for markup and stylesheets — so an inline image in .html, .css
// or .md was never checked. nox's own dashboard.html carries a base64 PNG on a
// single 28KB line and reported 8 high-severity vendor "API key" findings from
// it on every self-scan. The marker is unambiguous in raw bytes, so this check
// needs no language at all.
func inDataURIPayload(content []byte, f *findings.Finding) bool {
	start := lexctx.LineColToOffset(content, f.Location.StartLine, f.Location.StartColumn)
	if start < 0 || start > len(content) {
		return false
	}

	// Walk the data: URIs that begin before the match and test whether the
	// match falls within one's payload. Files carry few data: URIs, and the
	// scan stops at the first one starting after the match.
	for off := 0; off < start; {
		rel := bytes.Index(content[off:], dataURIScheme)
		if rel < 0 {
			return false
		}
		uriStart := off + rel
		if uriStart >= start {
			return false
		}

		payloadStart, ok := base64PayloadStart(content, uriStart)
		if !ok {
			off = uriStart + len(dataURIScheme)
			continue
		}
		if start >= payloadStart && start < payloadEnd(content, payloadStart) {
			return true
		}
		off = uriStart + len(dataURIScheme)
	}
	return false
}

// base64PayloadStart returns the offset just past ";base64," for the data: URI
// beginning at uriStart, provided the marker appears in that URI's declaration
// rather than somewhere later in the file.
func base64PayloadStart(content []byte, uriStart int) (int, bool) {
	// A data: URI declaration (`data:image/png;base64,`) is short. Bounding the
	// search keeps a bare `data:` elsewhere in the file from pairing with a
	// distant ";base64," and swallowing everything between them.
	const maxDeclaration = 128
	end := min(uriStart+maxDeclaration, len(content))

	rel := bytes.Index(content[uriStart:end], dataURIMarker)
	if rel < 0 {
		return 0, false
	}
	return uriStart + rel + len(dataURIMarker), true
}

// payloadEnd returns the offset at which the base64 payload starting at
// payloadStart ends — the first character that cannot appear in one.
func payloadEnd(content []byte, payloadStart int) int {
	for i := payloadStart; i < len(content); i++ {
		if !isBase64Byte(content[i]) {
			return i
		}
	}
	return len(content)
}

func isBase64Byte(b byte) bool {
	switch {
	case b >= 'A' && b <= 'Z',
		b >= 'a' && b <= 'z',
		b >= '0' && b <= '9':
		return true
	}
	return b == '+' || b == '/' || b == '=' || b == '-' || b == '_'
}
