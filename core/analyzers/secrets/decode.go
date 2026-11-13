// Package secrets implements pattern-based secret detection.
package secrets

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"strconv"
	"strings"

	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/rules"
)

// DecodedSegment represents a decoded portion of file content.
type DecodedSegment struct {
	Original    string
	Decoded     string
	Encoding    string // "base64" or "hex"
	StartOffset int    // byte offset in original content
}

// minEncodedLen is the shortest run of encoding characters treated as an
// encoded segment.
const minEncodedLen = 40

var base64Chars, hexChars [256]bool

func init() {
	for _, c := range "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" {
		base64Chars[c] = true
	}
	for _, c := range "0123456789abcdefABCDEF" {
		hexChars[c] = true
	}
}

// base64Spans reports the [start, end) spans of base64 candidates: exactly
// the leftmost-first matches of `[A-Za-z0-9+/]{40,}={0,2}`.
//
// It replaced that regular expression, and the expression it replaced is the
// test oracle. Go's regexp runs an automaton from every position in the file;
// on crewAI the two segment patterns cost 67s of a 373s scan -- more than the
// decoding and the rescans of everything they found, which cost 0.3s. A run of
// one character class needs no automaton: every match is a maximal run.
func base64Spans(content []byte) [][2]int {
	return classRuns(content, &base64Chars, 2)
}

// hexSpans reports the [start, end) spans of hex candidates: exactly the
// leftmost-first matches of `(?i)[0-9a-f]{40,}`. Case folding adds only A-F;
// neither fold outlier (U+212A KELVIN SIGN, U+017F LONG S) folds into a-f.
func hexSpans(content []byte) [][2]int {
	return classRuns(content, &hexChars, 0)
}

// classRuns returns every maximal run of class bytes at least minEncodedLen
// long, each extended by up to maxPad '=' bytes. Byte-wise scanning is exact:
// both classes are ASCII, and no byte of a multi-byte or invalid UTF-8
// sequence is in either.
func classRuns(content []byte, class *[256]bool, maxPad int) [][2]int {
	var spans [][2]int
	for i := 0; i < len(content); {
		if !class[content[i]] {
			i++
			continue
		}
		start := i
		for i < len(content) && class[content[i]] {
			i++
		}
		if i-start < minEncodedLen {
			continue
		}
		for pad := 0; pad < maxPad && i < len(content) && content[i] == '='; pad++ {
			i++
		}
		spans = append(spans, [2]int{start, i})
	}
	return spans
}

// decodeBase64Segments finds and decodes base64-encoded strings in content.
func decodeBase64Segments(content []byte) []DecodedSegment {
	var segments []DecodedSegment
	for _, loc := range base64Spans(content) {
		raw := string(content[loc[0]:loc[1]])
		decoded, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			// Try URL-safe encoding.
			decoded, err = base64.URLEncoding.DecodeString(raw)
			if err != nil {
				continue
			}
		}
		// Only keep decoded content that looks like text (printable ASCII).
		if !isPrintable(decoded) {
			continue
		}
		segments = append(segments, DecodedSegment{
			Original:    raw,
			Decoded:     string(decoded),
			Encoding:    "base64",
			StartOffset: loc[0],
		})
	}
	return segments
}

// decodeHexSegments finds and decodes hex-encoded strings in content.
func decodeHexSegments(content []byte) []DecodedSegment {
	var segments []DecodedSegment
	for _, loc := range hexSpans(content) {
		raw := string(content[loc[0]:loc[1]])
		// Hex strings must have even length.
		if len(raw)%2 != 0 {
			continue
		}
		decoded, err := hex.DecodeString(strings.ToLower(raw))
		if err != nil {
			continue
		}
		if !isPrintable(decoded) {
			continue
		}
		segments = append(segments, DecodedSegment{
			Original:    raw,
			Decoded:     string(decoded),
			Encoding:    "hex",
			StartOffset: loc[0],
		})
	}
	return segments
}

// isPrintable returns true if the data consists mostly of printable ASCII characters.
func isPrintable(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	printable := 0
	for _, b := range data {
		if b >= 0x20 && b <= 0x7e {
			printable++
		}
	}
	return float64(printable)/float64(len(data)) > 0.8
}

// DecodeAndScan decodes base64/hex segments in content and scans the decoded
// content against the provided rules engine. Findings reference the original
// file position and note the encoding in Metadata.
//
// The location remap is the whole reason StartOffset is recorded. The engine
// scans the DECODED bytes, so every match comes back positioned inside the
// decoded string -- which for a single-line payload means line 1, at a column
// that indexes the plaintext. Reported unchanged, those coordinates name a
// place in the file that has nothing to do with the finding: measured on
// crewAI's recorded cassettes, 95 of 578 SEC-161 findings pointed at line 1,
// columns 9-41, of a file whose line 1 is `interactions:` -- 13 characters
// long. An operator following that location finds nothing, and cannot tell
// whether the finding is wrong or they are looking in the wrong place.
//
// So each match is moved onto the span of the ENCODED segment in the source,
// which is the text someone actually has to go and look at.
func DecodeAndScan(content []byte, path string, engine *rules.Engine) []findings.Finding {
	var results []findings.Finding

	segments := decodeBase64Segments(content)
	segments = append(segments, decodeHexSegments(content)...)

	for _, seg := range segments {
		matches, err := engine.ScanFile(path, []byte(seg.Decoded))
		if err != nil {
			continue
		}
		// When the decoded bytes are themselves an image/markup/data blob (a
		// base64 SVG, an embedded font, an inline PNG), the long alphanumeric
		// runs inside them trip the entropy rules but are never credentials.
		// Drop entropy-only findings in that case. A real secret hidden in
		// base64 decodes to a bare credential — not to markup — so the provider
		// pattern rules still fire and the secret is still caught.
		blob := decodedIsBlob(seg.Decoded)
		for j := range matches {
			if blob && isEntropyRule(matches[j].RuleID) {
				continue
			}
			// Copy metadata to avoid mutating the shared rule metadata map.
			meta := make(map[string]string, len(matches[j].Metadata)+2)
			for k, v := range matches[j].Metadata {
				meta[k] = v
			}
			meta["encoding"] = seg.Encoding
			meta["encoded_value"] = truncateString(seg.Original, 80)
			// Where the match sat inside the decoded plaintext. Kept because
			// it is the only way back to the matched bytes once the location
			// points at the encoded span instead.
			meta["decoded_line"] = strconv.Itoa(matches[j].Location.StartLine)
			meta["decoded_column"] = strconv.Itoa(matches[j].Location.StartColumn)
			matches[j].Metadata = meta
			relocateToSegment(&matches[j], content, seg)
			results = append(results, matches[j])
		}
	}

	return results
}

// relocateToSegment moves a finding from decoded coordinates onto the encoded
// segment it came from, in the source file.
func relocateToSegment(f *findings.Finding, content []byte, seg DecodedSegment) {
	startLine, startCol := offsetToPosition(content, seg.StartOffset)
	endLine, endCol := offsetToPosition(content, seg.StartOffset+len(seg.Original))
	f.Location.StartLine = startLine
	f.Location.StartColumn = startCol
	f.Location.EndLine = endLine
	f.Location.EndColumn = endCol
}

// offsetToPosition converts a byte offset into 1-based line and column. An
// offset past the end clamps to the end, so a malformed segment cannot produce
// a location outside the file.
func offsetToPosition(content []byte, off int) (line, col int) {
	if off < 0 {
		off = 0
	}
	if off > len(content) {
		off = len(content)
	}
	line = 1 + bytes.Count(content[:off], []byte{'\n'})
	lineStart := bytes.LastIndexByte(content[:off], '\n') + 1
	return line, off - lineStart + 1
}

// entropyRuleIDs are the entropy-based secret rules (Shannon-entropy matcher,
// no provider pattern). They flag high-randomness strings that "look like"
// secrets and are the class prone to firing on decoded image/markup blobs.
var entropyRuleIDs = map[string]struct{}{
	"SEC-161": {},
	"SEC-162": {},
	"SEC-163": {},
}

// isEntropyRule reports whether a rule ID is an entropy-only secret rule.
func isEntropyRule(ruleID string) bool {
	_, ok := entropyRuleIDs[ruleID]
	return ok
}

// decodedIsBlob reports whether decoded content is itself a markup/image/binary
// data blob rather than a plain credential. SVG/XML/HTML markup and common
// image magic headers decode from data-URI payloads; a real hidden secret
// decodes to a short credential string, not to markup, so this stays false for
// genuine encoded secrets. Deterministic and content-only.
func decodedIsBlob(decoded string) bool {
	trimmed := strings.TrimSpace(decoded)
	if trimmed == "" {
		return false
	}
	// Markup blobs: SVG/XML/HTML documents embedded as data URIs.
	lower := strings.ToLower(trimmed)
	if strings.HasPrefix(lower, "<svg") ||
		strings.HasPrefix(lower, "<?xml") ||
		strings.HasPrefix(lower, "<!doctype") ||
		strings.HasPrefix(lower, "<html") {
		return true
	}
	// Image magic headers surviving the printable-ASCII filter (e.g. GIF).
	for _, sig := range imageMagicPrefixes {
		if strings.HasPrefix(decoded, sig) {
			return true
		}
	}
	return false
}

// imageMagicPrefixes are leading byte signatures of common image formats that
// remain (mostly) printable after base64 decoding.
var imageMagicPrefixes = []string{
	"GIF87a", "GIF89a", // GIF
	"%PDF-", // PDF documents embedded as data URIs
}

// truncateString truncates a string to maxLen characters with an ellipsis.
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
