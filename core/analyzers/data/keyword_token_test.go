package data

import "testing"

// DATA-009's keyword `tin` sits inside setting, testing and routing; DATA-004's
// `tel` inside hotel; DATA-005's `ip` inside zip. The pre-filter matched them as
// substrings, so these rules ran their whole-file, case-insensitive regex on
// most files (DATA-009 alone cost 80 s on crewAI for zero findings, #736). And
// where the longer word ENDS in the keyword -- martin:, hotel:, zip = -- the
// pattern itself matched the tail.
func TestAKeywordInsideAWordIsNotTheKeyword(t *testing.T) {
	a := NewAnalyzer()
	for _, c := range []struct{ rule, line string }{
		{"DATA-009", `martin: 12 345 67890`},
		{"DATA-009", `latin = 12/345/67890`},
		{"DATA-004", `hotel: "212 555 0237"`},
		{"DATA-005", `zip = "8.8.4.4"`},
	} {
		if scanFires(t, a, c.rule, c.line+"\n") {
			t.Errorf("%s matched a keyword inside a longer word: %s", c.rule, c.line)
		}
	}
	for _, c := range []struct{ rule, line string }{
		{"DATA-009", `tin: 12/345/67890`},
		{"DATA-009", `customer_tin = 123 456 78901`},
		{"DATA-009", `TIN=12/345/6789`},
		{"DATA-004", `tel: "212 555 0237"`},
		{"DATA-004", `user_phone: "212 555 0237"`},
		{"DATA-005", `server_ip = "8.8.4.4"`},
		{"DATA-005", `host: 8.8.4.4`},
	} {
		if !scanFires(t, a, c.rule, c.line+"\n") {
			t.Errorf("%s no longer matches its keyword as a word: %s", c.rule, c.line)
		}
	}
}
