package data

import (
	"strings"
	"testing"
)

// DATA-003 claims a payment card number is present in the source, at HIGH
// severity. Its pattern describes only the SHAPE of one: an issuer prefix and a
// length. What makes a digit run an actual card is the Luhn checksum.
//
// Because the pattern is anchored with `\b` and `.` is not a word character,
// the digits after a decimal point are word-bounded — so any float whose
// fractional part is 16 digits starting 4, 5, 3 or 6 matched. Measured on the
// pinned corpus: 560 findings, ALL of them floats in embedding vectors and
// notebook output, e.g. `Similarity: 0.6522269248962402` reported as a
// Discover card. 52 of the 560 (9.3%) passed Luhn, which is what chance
// predicts — so the checksum alone was not enough, and neither is context
// alone. Both are required, and neither is a heuristic: a real card is written
// "4111111111111111", never 0.4111111111111111.

// TestRealCardNumbersAreReported is the recall this rule exists for. These are
// the standard test numbers published by the card networks; all satisfy Luhn.
func TestRealCardNumbersAreReported(t *testing.T) {
	a := NewAnalyzer()
	for name, card := range map[string]string{
		"Visa":       "4111111111111111",
		"Mastercard": "5555555555554444",
		"Amex":       "378282246310005",
		"Discover":   "6011111111111117",
	} {
		got, err := a.ScanFile("payments.py", []byte("card = \""+card+"\"\n"))
		if err != nil {
			t.Fatal(err)
		}
		var found bool
		for _, f := range got {
			if f.RuleID == "DATA-003" {
				found = true
			}
		}
		if !found {
			t.Errorf("DATA-003 does not report a %s test card (%s)", name, card)
		}
	}
}

// TestAFloatIsNotACard is the 560-finding false-positive class.
func TestAFloatIsNotACard(t *testing.T) {
	a := NewAnalyzer()
	for _, line := range []string{
		`"**Similarity:** 0.6522269248962402<br>"`,
		`embedding=[0.004466439131647348, -0.6573537588119507]`,
		`"query_ease: 0.5334109647649754"`,
		// Passes Luhn by chance, and is still a float.
		`score = 0.6595195531845093`,
	} {
		got, err := a.ScanFile("notebook.ipynb", []byte(line+"\n"))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range got {
			if f.RuleID == "DATA-003" {
				t.Errorf("DATA-003 reported a credit card in %q — that is the fractional "+
					"part of a decimal number", line)
			}
		}
	}
}

// TestLuhnRejectsAShapedNonCard keeps the checksum honest on its own.
func TestLuhnRejectsAShapedNonCard(t *testing.T) {
	if isPaymentCardNumber("4111111111111112") {
		t.Error("a Visa-shaped run failing Luhn was accepted as a card")
	}
	if !isPaymentCardNumber("4111111111111111") {
		t.Error("a valid Visa test card was rejected")
	}
	if isPaymentCardNumber(strings.Repeat("4", 16)) {
		t.Error("4444444444444444 does not satisfy Luhn and was accepted")
	}
}

// TestALeadingDotWithNoDigitIsNotADecimal. `.6011111111111117` at the start of
// a token is not the fractional part of anything, so the filter must not fire.
func TestALeadingDotWithNoDigitIsNotADecimal(t *testing.T) {
	a := NewAnalyzer()
	got, err := a.ScanFile("x.py", []byte("card = \".6011111111111117\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, f := range got {
		if f.RuleID == "DATA-003" {
			found = true
		}
	}
	if !found {
		t.Error("the decimal filter swallowed a card preceded by a dot that follows no " +
			"digit; it is meant to identify a FRACTIONAL part, not any dot")
	}
}
