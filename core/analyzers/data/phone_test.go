package data

import "testing"

// DATA-004 reports a US phone number in configuration as personal data. On the
// 2026-09-27 head-to-head all 32 of its findings were numbers no person has:
// 28 x +1 415 555 0123 in openai-python's API reference ("such as
// tel:+14155550123"), in the 555-0100..0199 range the North American
// Numbering Plan reserves for fiction, and 4 x 1234567890 in llama_index.
func TestAFictionalPhoneNumberIsNotPersonalData(t *testing.T) {
	a := NewAnalyzer()
	for _, line := range []string{
		`target_uri = "tel:+14155550123"`,
		`phone: "(212) 555-0199"`,
		`phone = "1234567890"`,
		`mobile: "555-555-5555"`,
	} {
		if scanFires(t, a, "DATA-004", line+"\n") {
			t.Errorf("DATA-004 reported a number no person has: %s", line)
		}
	}
	for _, line := range []string{
		`phone: "(212) 555-0237"`, // 555 outside 0100-0199 is a real exchange range
		`phone = "4155551298"`,
		`mobile: "+1 646 872 3301"`,
	} {
		if !scanFires(t, a, "DATA-004", line+"\n") {
			t.Errorf("DATA-004 no longer reports a real-looking number: %s", line)
		}
	}
}
