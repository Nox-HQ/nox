package lexctx

import (
	"regexp"
	"testing"
)

// TestFPCollapse is the thesis of this package made executable. A single broad
// secret-shaped pattern appears three times in a realistic file:
//
//  1. in a live code assignment (a TRUE positive we must keep)
//  2. inside a base64 SVG data string blob (a FALSE positive)
//  3. inside a `//` comment (a FALSE positive)
//
// A naive text regex — exactly what Nox's SAST rules do today — fires on all
// three. Gating each raw match through the lexical-context classifier collapses
// the two non-code matches and keeps only the real one. This is the mechanism
// behind the 99.5%-noise reduction claim in the scan-of-the-week reports.
func TestFPCollapse(t *testing.T) {
	// The same 32-char token in all three positions.
	const token = "AKIA1234567890ABCDEF1234567890AB"

	// A realistic TS file. The token appears three times:
	//   1. as a genuine hardcoded secret in a short string literal (a TRUE
	//      positive — a rule MUST keep this),
	//   2. buried inside a base64 SVG data-URI string blob (a FALSE positive),
	//   3. inside a `//` comment (a FALSE positive).
	//
	// Note (1) and (2) are BOTH strings: the discriminator is not the lexical
	// kind alone but whether the string is a short literal or a data blob. That
	// is exactly what SuppressNonCode encodes and why it is safe for secrets.
	// The base64 chunks are broken by '/' so the token is the only 32-char run
	// inside the blob — keeping the "exactly 3 raw matches" assertion clean.
	src := "const awsKey = \"" + token + "\";\n" +
		"const icon = \"data:image/svg+xml;base64,PHN2/" + token + "/Zz4=\";\n" +
		"// legacy key was " + token + " rotate before removing\n" +
		"export { awsKey };\n"

	// A deliberately broad, high-noise pattern: any 32-char alphanumeric run.
	// This is the archetype that generates the false-positive flood.
	re := regexp.MustCompile(`[A-Za-z0-9]{32}`)

	rawMatches := re.FindAllStringIndex(src, -1)
	if len(rawMatches) != 3 {
		t.Fatalf("fixture precondition: expected 3 raw regex matches, got %d", len(rawMatches))
	}

	lang := LangFromPath("keys.ts")
	if lang != LangJavaScript {
		t.Fatalf("fixture precondition: expected JS/TS, got %v", lang)
	}
	regions := Classify(lang, []byte(src))
	regionsCover(t, regions, len(src))

	// Gate every raw match through the analyzer-facing helper. This is exactly
	// the call a secrets/ai analyzer would add: keep a match only if it is NOT
	// suppressed as non-code.
	var survivors [][]int
	kinds := make([]Kind, 0, len(rawMatches))
	for _, m := range rawMatches {
		kinds = append(kinds, KindAt(regions, m[0]))
		if !SuppressNonCode(lang, []byte(src), m[0], m[1]) {
			survivors = append(survivors, m)
		}
	}

	// Exactly the genuine hardcoded secret survives the gate; the base64 blob
	// and the comment are collapsed.
	if len(survivors) != 1 {
		t.Fatalf("expected exactly 1 survivor, got %d (kinds=%v)", len(survivors), kinds)
	}
	got := src[survivors[0][0]:survivors[0][1]]
	if got != token {
		t.Errorf("survivor = %q, want the token %q", got, token)
	}
	// The survivor is a string literal (the real secret), proving we did NOT
	// blanket-suppress strings — only the data-blob string.
	if k := KindAt(regions, survivors[0][0]); k != KindString {
		t.Errorf("survivor should be a (short) string literal, got kind %v", k)
	}

	// Cross-check: the two suppressed matches are precisely the blob string and
	// the comment — proving we drop the right ones, not just the right count.
	var sawBlob, sawComment bool
	for i, m := range rawMatches {
		if !SuppressNonCode(lang, []byte(src), m[0], m[1]) {
			continue // the survivor
		}
		switch kinds[i] {
		case KindString:
			sawBlob = true
		case KindComment:
			sawComment = true
		}
	}
	if !sawBlob {
		t.Error("expected the base64 data-URI blob match to be suppressed")
	}
	if !sawComment {
		t.Error("expected the comment match to be suppressed")
	}
}

// TestFPCollapsePython mirrors the demonstration for Python's `#` comments and
// triple-quoted string blobs, the other big FP source. The true positive is a
// genuine hardcoded secret in a short literal; the FPs are a long triple-quoted
// base64 blob and a comment.
func TestFPCollapsePython(t *testing.T) {
	const token = "AKIA1234567890ABCDEF1234567890AB"
	// A long base64 data-URI embedded in a docstring, with the token buried
	// inside it — this string exceeds the blob threshold and is dropped.
	blob := "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAAB" + token + "kJggg=="
	src := "aws_key = \"" + token + "\"\n" +
		"PAYLOAD = \"\"\"\n" + blob + "\n\"\"\"\n" +
		"# old key " + token + " deprecated\n"

	// Gate each of the three token occurrences directly; the token substring is
	// unambiguous, and each occurrence lives in a distinct lexical context.
	assertGate := func(context string, occurrence int, wantSuppressed bool) {
		t.Helper()
		off := nthIndexOf(src, token, occurrence)
		if off < 0 {
			t.Fatalf("fixture: could not find occurrence %d of token", occurrence)
		}
		got := SuppressNonCode(LangPython, []byte(src), off, off+len(token))
		if got != wantSuppressed {
			t.Errorf("%s: SuppressNonCode = %v, want %v", context, got, wantSuppressed)
		}
	}
	assertGate("hardcoded secret in short literal", 0, false)
	assertGate("token in triple-quoted data blob", 1, true)
	assertGate("token in # comment", 2, true)
}
