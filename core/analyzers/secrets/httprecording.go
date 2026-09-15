package secrets

import (
	"bytes"
	"regexp"
	"strings"
)

// A recorded HTTP exchange is evidence about a past request, and almost all of
// it is traffic rather than credential material.
//
// The part that is not: an `authorization:` or `x-api-key:` header on the
// REQUEST, and a credential in the request URI. vcrpy does not filter headers
// unless `filter_headers` is configured, and forgetting to configure it is a
// well-known way to commit a live key. Those are the reason to scan a cassette
// at all.
//
// Everything else — response headers and bodies, request bodies, cookies in
// either direction — is what the wire carried. A Cloudflare `__cf_bm` cookie,
// an embedding vector, a request id and a recorded prompt are not credentials
// the repository holds, and nobody can rotate them.
//
// The gate applies to the ENTROPY rules only (SEC-161, SEC-162), which is the
// distinction that keeps it honest. A rule encoding a vendor's credential
// format has established what it found, and is allowed to say so anywhere in a
// recording — including in a request body, which is where an OAuth
// `client_secret` would sit. A rule that measures entropy has established that
// some bytes are random, and a recording is full of random bytes that are not
// credentials.
//
// The gap this leaves, stated rather than discovered later: a credential with
// NO recognised vendor format, hardcoded into a recorded request body, is
// reported by nothing. It would have been reported by entropy alone before.
// That is the price of the 254 findings this removes from one repository, and
// it is bounded by the provider rules covering every format nox knows.
//
// Measured on crewAI at 1.15.21, SEC-161/SEC-162 produced 540 findings and
// every one was inside a cassette. By what precedes the matched value:
//
//	202  __cf_bm            Cloudflare bot-management cookie (Set-Cookie)
//	148  (continuation)     later lines of a base64 response body
//	 58  id                 response/request identifiers
//	 44  embedding          base64 float32 vectors, up to 8,193 characters
//	 32  _cfuvid            Cloudflare visitor cookie (Set-Cookie)
//	 32  thoughtSignature   Gemini response metadata
//	  8  api_key            PostHog's phc_ project key — which the vendor
//	                        publishes, and which SEC-661 deliberately excludes
//	                        for that reason
//
// Not one was a credential the repository holds. The `api_key` group is the
// sharpest case: a rule was redesigned specifically to stop reporting a
// publishable key, and the generic entropy rule reported it anyway.

var (
	// cassetteMarkers are the top-level keys of the recorded-HTTP formats. All
	// of them are YAML; HAR (a JSON format with the same request/response
	// shape) is a known gap and is deliberately not guessed at here.
	cassetteMarkers = [][]byte{
		[]byte("\ninteractions:"),      // vcrpy, betamax
		[]byte("\nhttp_interactions:"), // ruby VCR
		[]byte("interactions:\n"),      // same, at offset 0
		[]byte("http_interactions:\n"),
	}
	requestKeyRe   = regexp.MustCompile(`(?m)^[ \t-]*request:[ \t]*$`)
	uriKeyRe       = regexp.MustCompile(`^[ \t]*(?i:uri|url):`)
	headersKeyRe   = regexp.MustCompile(`^[ \t]*headers:[ \t]*$`)
	headerNameRe   = regexp.MustCompile(`^[ \t]*([A-Za-z0-9_-]+):`)
	cookieHeaderRe = regexp.MustCompile(`^(?i:set-cookie|cookie)$`)
)

// byteSpan is a half-open byte range [start, end).
type byteSpan struct{ start, end int }

// isHTTPRecording reports whether content is a recorded HTTP exchange.
//
// The check reads the document rather than the filename. A cassette is
// conventionally under `tests/cassettes/`, but that is a convention: gating on
// the path would both miss cassettes stored elsewhere and, worse, suppress
// every genuine secret in any directory somebody happened to name that.
func isHTTPRecording(path string, content []byte) bool {
	if !strings.HasSuffix(strings.ToLower(path), ".yaml") &&
		!strings.HasSuffix(strings.ToLower(path), ".yml") {
		return false
	}
	head := content
	if len(head) > 64*1024 {
		head = head[:64*1024]
	}
	var marked bool
	for _, m := range cassetteMarkers {
		if bytes.Contains(head, m) {
			marked = true
			break
		}
	}
	// The marker alone is not enough. A recording is a list of request/response
	// pairs, and the gate confines the entropy rules to the request side — so a
	// document carrying the marker and NO request block would have no
	// credential-bearing span at all, and every high-entropy value in it would
	// be gated. Requiring the structure means an unrelated YAML file that
	// happens to use the key `interactions:` is scanned normally.
	return marked && requestKeyRe.Match(head)
}

// credentialBearingSpans returns the byte ranges of a recording where a
// credential this repository holds can appear: within each `request:` block,
// the `uri:` line and every `headers:` entry that is not a cookie.
//
// YAML blocks are bounded by indentation — a block runs from its key to the
// first later non-blank line indented no further — and that is the whole rule,
// which is why this needs no YAML parser. A parser would additionally have to
// round-trip the cassette's scalars, frequently 8 KB of escaped JSON, to tell a
// caller where they started.
func credentialBearingSpans(content []byte) []byteSpan {
	lines := bytes.Split(content, []byte("\n"))
	offsets := make([]int, len(lines)+1)
	for i, l := range lines {
		offsets[i+1] = offsets[i] + len(l) + 1
	}
	// blockEnd returns the index of the first line after the block opened at i.
	//
	// A deeper indent continues the block, and so does a sequence item at the
	// SAME indent — which is how YAML writes a list under a mapping key, and
	// exactly how an HTTP header is written because a header may repeat:
	//
	//	      authorization:
	//	      - Bearer sk-proj-…
	//
	// Bounding on indentation alone ends the block at the key line and leaves
	// the value outside it, which for this file means the one credential worth
	// finding is classified as traffic.
	blockEnd := func(i, indent int) int {
		for j := i + 1; j < len(lines); j++ {
			if len(bytes.TrimSpace(lines[j])) == 0 {
				continue
			}
			w := leadingWidth(lines[j])
			if w > indent {
				continue
			}
			if w == indent && bytes.HasPrefix(bytes.TrimLeft(lines[j], " \t"), []byte("- ")) {
				continue
			}
			return j
		}
		return len(lines)
	}

	var spans []byteSpan
	for i := 0; i < len(lines); i++ {
		m := requestKeyRe.FindSubmatch(lines[i])
		if m == nil {
			continue
		}
		reqEnd := blockEnd(i, leadingWidth(lines[i]))
		for j := i + 1; j < reqEnd; j++ {
			switch {
			case uriKeyRe.Match(lines[j]):
				spans = append(spans, byteSpan{offsets[j], offsets[j+1]})
			case headersKeyRe.Match(lines[j]):
				hIndent := leadingWidth(lines[j])
				hEnd := blockEnd(j, hIndent)
				// Each header is its own key; skip the cookie ones.
				for k := j + 1; k < hEnd; k++ {
					hm := headerNameRe.FindSubmatch(lines[k])
					if hm == nil {
						continue
					}
					if cookieHeaderRe.Match(hm[1]) {
						continue
					}
					spans = append(spans, byteSpan{offsets[k], offsets[blockEnd(k, leadingWidth(lines[k]))]})
				}
				j = hEnd - 1
			}
		}
		i = reqEnd - 1
	}
	return spans
}

// leadingWidth counts leading spaces and tabs.
func leadingWidth(line []byte) int {
	n := 0
	for n < len(line) && (line[n] == ' ' || line[n] == '\t') {
		n++
	}
	return n
}

// inSpan reports whether the byte offset falls in any span.
func inSpan(spans []byteSpan, off int) bool {
	for _, s := range spans {
		if off >= s.start && off < s.end {
			return true
		}
	}
	return false
}

// entropyOnlyRules are the rules whose whole claim is that some bytes are
// random. Every other secret rule encodes a vendor format and is left to fire
// anywhere in a recording.
var entropyOnlyRules = map[string]bool{"SEC-161": true, "SEC-162": true}
