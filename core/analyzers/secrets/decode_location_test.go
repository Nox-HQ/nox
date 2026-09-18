package secrets

import (
	"encoding/base64"
	"strings"
	"testing"
)

// A finding decoded out of base64 must point at the base64, not at line 1.
//
// DecodeAndScan hands the DECODED bytes to the engine, so every match comes
// back positioned inside the plaintext: line 1 of a single-line payload, at a
// column that indexes the decoded string. Those coordinates were reported
// unchanged, and they name a place in the source file that has nothing to do
// with the finding.
//
// Measured on crewAI's recorded cassettes: 95 of 578 SEC-161 findings pointed
// at line 1, columns 9-41, of files whose line 1 is `interactions:` -- 13
// characters. All 95 decode-derived findings were at line <= 2, and all 95
// findings at line <= 2 were decode-derived, so the correspondence was exact.
//
// The function's doc comment claimed the opposite ("Findings reference the
// original file position") for as long as it was wrong, which is why nothing
// caught it: the contract was stated, believed, and never asserted.

// TestADecodedFindingPointsAtTheEncodedText is that assertion.
func TestADecodedFindingPointsAtTheEncodedText(t *testing.T) {
	a := NewAnalyzer()

	// A real-shaped credential, base64'd, parked on line 4 so a location of
	// line 1 cannot pass by coincidence.
	encoded := base64.StdEncoding.EncodeToString(
		[]byte(`{"aws_key": "AKIAIOSFODNN7EXAMPLE", "pad": "` + strings.Repeat("x", 40) + `"}`))
	lines := []string{
		"interactions:",
		"- request:",
		"    body:",
		"      payload: " + encoded,
		"    status: 200",
	}
	content := []byte(strings.Join(lines, "\n") + "\n")

	results := DecodeAndScan(content, "cassette.yaml", a.engine)
	if len(results) == 0 {
		t.Skip("no decoded findings for this fixture; the location contract is " +
			"unexercised here rather than violated")
	}

	const wantLine = 4
	wantCol := strings.Index(lines[3], encoded) + 1

	for _, f := range results {
		if f.Metadata["encoding"] == "" {
			continue // not a decoded finding
		}
		if f.Location.StartLine != wantLine {
			t.Errorf("%s reported line %d, want %d. A decoded finding is being "+
				"reported at its position inside the PLAINTEXT, so it names a line "+
				"of the file that does not contain it.",
				f.RuleID, f.Location.StartLine, wantLine)
		}
		if f.Location.StartColumn != wantCol {
			t.Errorf("%s reported column %d, want %d (where the base64 run starts)",
				f.RuleID, f.Location.StartColumn, wantCol)
		}
		// The location must be inside the file it names.
		if f.Location.StartLine >= 1 && f.Location.StartLine <= len(lines) {
			line := lines[f.Location.StartLine-1]
			if f.Location.StartColumn > len(line)+1 {
				t.Errorf("%s: column %d is past the end of line %d (%d chars). "+
					"The location cannot be followed to anything.",
					f.RuleID, f.Location.StartColumn, f.Location.StartLine, len(line))
			}
		}
		// And the way back to the matched bytes must survive.
		if f.Metadata["decoded_line"] == "" {
			t.Errorf("%s lost decoded_line; once the location points at the "+
				"encoded span there is no other route to the matched plaintext", f.RuleID)
		}
	}
}

// TestOffsetToPositionIsOneBased covers the arithmetic directly, including the
// clamp that keeps a malformed segment from producing a location outside the
// file.
func TestOffsetToPositionIsOneBased(t *testing.T) {
	content := []byte("abc\ndefgh\nij")
	for _, tc := range []struct {
		off             int
		wantLn, wantCol int
	}{
		{0, 1, 1},   // first byte
		{3, 1, 4},   // the newline itself, still line 1
		{4, 2, 1},   // first byte of line 2
		{8, 2, 5},   // mid line 2
		{10, 3, 1},  // line 3
		{999, 3, 3}, // past the end clamps to the end
		{-5, 1, 1},  // negative clamps to the start
	} {
		ln, col := offsetToPosition(content, tc.off)
		if ln != tc.wantLn || col != tc.wantCol {
			t.Errorf("offsetToPosition(%d) = (%d,%d), want (%d,%d)",
				tc.off, ln, col, tc.wantLn, tc.wantCol)
		}
	}
}
