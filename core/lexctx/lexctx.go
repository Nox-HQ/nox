package lexctx

// Kind labels the lexical role of a byte range.
type Kind int

// Kind values. KindCode is the only role a SAST match should be trusted in;
// KindString and KindComment are where the false positives live (base64 blobs,
// minified data, prose).
const (
	KindCode Kind = iota
	KindString
	KindComment
)

// String returns a stable lowercase label for the kind, used in test output and
// metadata.
func (k Kind) String() string {
	switch k {
	case KindString:
		return "string"
	case KindComment:
		return "comment"
	default:
		return "code"
	}
}

// Region is a half-open byte span [Start, End) with a single lexical Kind.
// Classify returns a contiguous, gap-free, ascending list of regions covering
// the whole input, so callers can binary-search by offset.
type Region struct {
	Start int
	End   int
	Kind  Kind
}

// Classify partitions content into contiguous lexical regions for the given
// language. The returned regions cover [0, len(content)) with no gaps or
// overlaps, in ascending order. For LangUnknown (or empty input of a known
// language) it returns a single KindCode region spanning the whole file, which
// is the graceful-degrade contract: gating on lexctx then suppresses nothing
// and behaves exactly like today.
func Classify(lang Lang, content []byte) []Region {
	if len(content) == 0 {
		return nil
	}
	switch lang {
	case LangPython:
		return scanPython(content)
	case LangJavaScript:
		return scanJavaScript(content)
	case LangGo:
		return scanGo(content)
	case LangPHP:
		return scanPHP(content)
	case LangJava:
		return scanJava(content)
	case LangRuby:
		return scanRuby(content)
	case LangRust:
		return scanRust(content)
	case LangCSharp:
		return scanCSharp(content)
	case LangCPP:
		return scanCPP(content)
	case LangPerl:
		return scanPerl(content)
	case LangScala:
		return scanScala(content)
	case LangKotlin:
		return scanKotlin(content)
	case LangShell:
		return scanShell(content)
	case LangPowerShell:
		return scanPowerShell(content)
	case LangSwift:
		return scanSwift(content)
	case LangObjC:
		return scanObjC(content)
	case LangLua:
		return scanLua(content)
	case LangClojure:
		return scanClojure(content)
	case LangElixir:
		return scanElixir(content)
	case LangDart:
		return scanDart(content)
	case LangGroovy:
		return scanGroovy(content)
	case LangYAML, LangDockerfile:
		return scanConfig(content)
	default:
		return []Region{{Start: 0, End: len(content), Kind: KindCode}}
	}
}

// regionBuilder accumulates regions and coalesces adjacent runs of the same
// Kind so callers see the minimal region list. It tracks the start of the
// current open run and the Kind it is emitting.
type regionBuilder struct {
	regions []Region
	// runStart is the offset where the current same-Kind run began.
	runStart int
	runKind  Kind
	started  bool
}

// emit records that the bytes of [from, to) have kind k. Runs of the same kind
// are merged; a change in kind flushes the previous run. Callers must invoke
// emit for strictly increasing, contiguous spans and call finish at the end.
func (b *regionBuilder) emit(from, to int, k Kind) {
	if to <= from {
		return
	}
	if !b.started {
		b.runStart = from
		b.runKind = k
		b.started = true
		return
	}
	if k == b.runKind {
		return // extend the current run; End is computed at flush time
	}
	b.regions = append(b.regions, Region{Start: b.runStart, End: from, Kind: b.runKind})
	b.runStart = from
	b.runKind = k
}

// finish flushes the trailing run up to end and returns the region list.
func (b *regionBuilder) finish(end int) []Region {
	if b.started && end > b.runStart {
		b.regions = append(b.regions, Region{Start: b.runStart, End: end, Kind: b.runKind})
	}
	return b.regions
}

// KindAt returns the Kind of the region containing offset, or KindCode if the
// offset falls outside every region (defensive: out-of-range offsets are
// treated as code so a bad offset never spuriously suppresses a finding).
// Regions are assumed sorted and non-overlapping, so this binary-searches.
func KindAt(regions []Region, offset int) Kind {
	lo, hi := 0, len(regions)
	for lo < hi {
		mid := int(uint(lo+hi) >> 1)
		switch {
		case offset < regions[mid].Start:
			hi = mid
		case offset >= regions[mid].End:
			lo = mid + 1
		default:
			return regions[mid].Kind
		}
	}
	return KindCode
}

// InCode reports whether the entire half-open span [start, end) lies within
// code regions. A match straddling a code/non-code boundary is NOT code — we
// require every byte of the span to be code so a regex that begins in a comment
// and leaks into code (or vice versa) is treated as suspect. An empty or
// inverted span is not considered code.
func InCode(regions []Region, start, end int) bool {
	if end <= start {
		return false
	}
	pos := start
	for pos < end {
		idx := regionIndexAt(regions, pos)
		if idx < 0 || regions[idx].Kind != KindCode {
			return false
		}
		// Advance to the end of this code region; if it already covers the
		// span we are done.
		if regions[idx].End >= end {
			return true
		}
		pos = regions[idx].End
	}
	return true
}

// regionIndexAt returns the index of the region containing offset, or -1.
func regionIndexAt(regions []Region, offset int) int {
	lo, hi := 0, len(regions)
	for lo < hi {
		mid := int(uint(lo+hi) >> 1)
		switch {
		case offset < regions[mid].Start:
			hi = mid
		case offset >= regions[mid].End:
			lo = mid + 1
		default:
			return mid
		}
	}
	return -1
}

// SuppressNonCode is the reusable post-filter for analyzers: given a raw regex
// match at [matchStart, matchEnd) in content, it returns true when the match
// should be DROPPED as a likely false positive.
//
// A match is dropped when it lies inside:
//
//   - a comment (always — prose and commented-out code are never live), or
//   - a string that is a DATA BLOB, not an ordinary literal. This is the
//     crucial distinction for secret detection: a hardcoded secret genuinely
//     lives in a short string literal (`key = "AKIA..."`) and MUST be kept,
//     whereas the same pattern buried inside a base64 data-URI, a minified
//     bundle, or a long encoded payload is noise and is dropped. blobFraction
//     encodes that "is this string data rather than a literal" heuristic.
//
// This asymmetry is why the helper is safe for the secrets analyzer to adopt:
// it removes the base64/minified/comment FP class without silencing real
// hardcoded-secret-in-string findings. Callers wanting strict code-only gating
// (e.g. AST-shaped rules) should use InCode directly instead.
//
// It classifies content itself for convenience; analyzers scanning a file many
// times should call Classify once and reuse the regions. For LangUnknown this
// always returns false (never suppress), preserving the graceful-degrade
// guarantee.
func SuppressNonCode(lang Lang, content []byte, matchStart, matchEnd int) bool {
	if lang == LangUnknown {
		return false
	}
	if matchEnd <= matchStart || matchStart < 0 || matchEnd > len(content) {
		return false
	}
	regions := Classify(lang, content)
	idx := regionIndexAt(regions, matchStart)
	if idx < 0 {
		return false
	}
	r := regions[idx]
	// A match straddling regions (leaking out of a comment/string into code) is
	// suspect but not clearly noise — keep it so we never hide a real finding.
	if r.End < matchEnd {
		return false
	}
	switch r.Kind {
	case KindComment:
		return true
	case KindString:
		return isStringBlob(content, r)
	default:
		return false
	}
}

// InDataBlob reports whether the match [matchStart,matchEnd) lies entirely
// inside a data-blob string literal (a long/base64 or data: URI string) — the
// class that produces the overwhelming majority of secret and pattern false
// positives (a 32-char alphanumeric run inside an embedded base64 SVG). Unlike
// SuppressNonCode, it does NOT drop comment matches: a credential written in a
// comment is often a real leaked secret, so the secrets analyzer must keep it.
// Use this for secret detection; use SuppressNonCode for code-pattern families
// where a match in a comment is never executable and is safe to drop.
func InDataBlob(lang Lang, content []byte, matchStart, matchEnd int) bool {
	if lang == LangUnknown {
		return false
	}
	if matchEnd <= matchStart || matchStart < 0 || matchEnd > len(content) {
		return false
	}
	regions := Classify(lang, content)
	idx := regionIndexAt(regions, matchStart)
	if idx < 0 {
		return false
	}
	r := regions[idx]
	if r.End < matchEnd { // straddles into code — keep, never hide a real finding
		return false
	}
	return r.Kind == KindString && isStringBlob(content, r)
}

// blobThreshold is the string length (in bytes, excluding delimiters) above
// which a string literal is considered a data blob rather than an ordinary
// literal. Real hardcoded secrets and config values are short; base64 payloads,
// data-URIs, and minified chunks are long. 96 bytes comfortably clears the
// longest real credentials (a GitHub PAT is ~40 chars, a JWT header segment is
// short) while catching data-URI/base64 blobs, which run to hundreds of bytes.
const blobThreshold = 96

// isStringBlob reports whether the string region r is a data blob rather than
// an ordinary literal. A string is a blob if it is very long, or if it is a
// data-URI (the single most common SVG/base64 FP carrier). Deterministic and
// content-only — no heurist­ic that depends on scan order or environment.
func isStringBlob(content []byte, r Region) bool {
	body := content[r.Start:r.End]
	// A structurally valid JWT is a credential, not an opaque payload, and it
	// is often long — a full token runs to hundreds of bytes. The length
	// heuristic below cannot tell it from a base64 image chunk, so it must
	// defer to the structural check, or nox drops real hardcoded JWTs as data
	// blobs. That was happening: blobThreshold's own comment reasoned about "a
	// JWT header segment" and missed that the whole token is long.
	if LooksLikeJWT(string(body)) {
		return false
	}
	if len(body) > blobThreshold {
		return true
	}
	return containsDataURI(body)
}

// containsDataURI reports whether body holds a `data:` URI scheme marker, the
// hallmark of an embedded base64 image/font blob.
func containsDataURI(body []byte) bool {
	const marker = "data:"
	for i := 0; i+len(marker) <= len(body); i++ {
		if string(body[i:i+len(marker)]) == marker {
			return true
		}
	}
	return false
}
