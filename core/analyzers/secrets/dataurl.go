package secrets

import (
	"bytes"
	"regexp"
	"strings"

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
	return inDataURIPayloadAt(content, dataURIStarts(content), f)
}

// dataURIStarts returns the offset of every "data:" in content, ascending.
// The scheme cannot overlap itself, so this is exactly the sequence a walk
// that resumes after each occurrence visits.
func dataURIStarts(content []byte) []int {
	var starts []int
	for off := 0; ; {
		rel := bytes.Index(content[off:], dataURIScheme)
		if rel < 0 {
			return starts
		}
		starts = append(starts, off+rel)
		off += rel + len(dataURIScheme)
	}
}

// inDataURIPayloadAt is inDataURIPayload with the file's data: URI offsets
// computed once by the caller. Searching the file afresh for every finding
// read the whole file per finding when it held no data: URI at all -- the
// common case -- which made a file's cost findings x size.
func inDataURIPayloadAt(content []byte, uriStarts []int, f *findings.Finding) bool {
	start := lexctx.LineColToOffset(content, f.Location.StartLine, f.Location.StartColumn)
	if start < 0 || start > len(content) {
		return false
	}

	// Walk the data: URIs that begin before the match and test whether the
	// match falls within one's payload.
	for _, uriStart := range uriStarts {
		if uriStart >= start {
			return false
		}
		payloadStart, ok := base64PayloadStart(content, uriStart)
		if !ok {
			continue
		}
		if start >= payloadStart && start < payloadEnd(content, payloadStart) {
			return true
		}
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

// imageBase64Signatures are how the first bytes of common image formats read
// once base64-encoded: PNG's \x89PNG\r\n\x1a\n, JPEG's \xff\xd8\xff, GIF's
// GIF8, and WebP's RIFF header. A string that starts with one is an image.
var imageBase64Signatures = [][]byte{
	[]byte("iVBORw0KGgo"), // PNG
	[]byte("/9j/"),        // JPEG
	[]byte("R0lGOD"),      // GIF
	[]byte("UklGR"),       // WebP (RIFF)
}

// inBase64ImageString reports whether a finding's match lies inside a quoted
// string whose content is a base64-encoded image.
//
// inDataURIPayload needs the `data:<mime>;base64,` prefix, and a notebook's
// outputs and a recorded API response carry images without one:
// "image/png": "iVBORw0KGgo…", "data": "/9j/4AAQ…". Any long enough base64 run
// contains any short vendor prefix, so these fired vendor rules by the dozen.
// The image's own signature at the start of the string is as unambiguous as
// the data: marker, and a credential never starts with one.
func inBase64ImageString(content []byte, f *findings.Finding) bool {
	open := enclosingStringOpen(content, f)
	if open < 0 {
		return false
	}
	body := content[open+1:]
	for _, sig := range imageBase64Signatures {
		if bytes.HasPrefix(body, sig) {
			return true
		}
	}
	return false
}

// enclosingStringOpen returns the offset of the quote that opens the string a
// finding's match sits in, or -1: the nearest quote before the match on the
// same line. It is only meaningful for opaque encoded values (base64 has no
// quotes, so none can sit between such a string's start and a match inside
// it), which is all its callers ask about.
func enclosingStringOpen(content []byte, f *findings.Finding) int {
	start := lexctx.LineColToOffset(content, f.Location.StartLine, f.Location.StartColumn)
	if start <= 0 || start > len(content) {
		return -1
	}
	for open := start - 1; open >= 0; open-- {
		switch content[open] {
		case '"', '\'':
			return open
		case '\n':
			return -1
		}
	}
	return -1
}

// modelCiphertextKeys are the JSON keys under which model APIs hand back
// ciphertext they issued and will take back: Anthropic's thinking-block
// signature and web-search encrypted_index, OpenAI's reasoning
// encrypted_content, Gemini's thoughtSignature.
var modelCiphertextKeys = map[string]bool{
	"signature":         true,
	"thoughtsignature":  true,
	"thought_signature": true,
	"encrypted_content": true,
	"encrypted_index":   true,
}

// modelCiphertextKey matches the end of `"<key>": ` before a string value.
var modelCiphertextKey = regexp.MustCompile(`"([A-Za-z_]+)"\s*:\s*$`)

// inModelCiphertext reports whether a finding's match lies in the string value
// of one of modelCiphertextKeys. Such a value is opaque provider ciphertext in
// recorded traffic: long base64, so the entropy rule and short-prefix vendor
// rules fired inside it (67 findings on the 2026-09-27 head-to-head), and
// never a credential this repository holds.
func inModelCiphertext(content []byte, f *findings.Finding) bool {
	open := enclosingStringOpen(content, f)
	if open < 0 {
		return false
	}
	lineStart := bytes.LastIndexByte(content[:open], '\n') + 1
	m := modelCiphertextKey.FindSubmatch(content[lineStart:open])
	return len(m) == 2 && modelCiphertextKeys[strings.ToLower(string(m[1]))]
}
