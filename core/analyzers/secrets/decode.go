// Package secrets implements pattern-based secret detection.
package secrets

import (
	"encoding/base64"
	"encoding/hex"
	"regexp"
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

var (
	reBase64 = regexp.MustCompile(`[A-Za-z0-9+/]{40,}={0,2}`)
	reHex    = regexp.MustCompile(`(?i)[0-9a-f]{40,}`)
)

// decodeBase64Segments finds and decodes base64-encoded strings in content.
func decodeBase64Segments(content []byte) []DecodedSegment {
	var segments []DecodedSegment
	for _, loc := range reBase64.FindAllIndex(content, -1) {
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
	for _, loc := range reHex.FindAllIndex(content, -1) {
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
			matches[j].Metadata = meta
			results = append(results, matches[j])
		}
	}

	return results
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
