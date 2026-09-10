package secrets

import "testing"

// TestSEC457WordBoundary covers SEC-457 (Iterable API key, pattern [a-z0-9]{32})
// firing on 40-character git SHAs inside JSON test data.
//
// princeton-nlp/SWE-agent's debug_20240322.json contained values like
// "commit": "953f29f700a60fc09b08b2c2270c12c447490c6a". Without word boundaries
// the bare [a-z0-9]{32} pattern matched the first 32 characters of the 40-char
// hex string — 18 high-severity false positives in a single file, every time
// the word "iterable" appeared anywhere in the file (e.g. Python's typing.Iterable).
//
// The fix adds \b anchors and secretShape validation, matching the precedent set
// by the neighbouring SEC-455 (Segment) rule.
func TestSEC457WordBoundary(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want bool
	}{
		{
			name: "40-char git SHA in JSON with iterable keyword in key name",
			src:  `{"iterable_cursor": null, "commit": "953f29f700a60fc09b08b2c2270c12c447490c6a"}`,
			want: false,
		},
		{
			name: "real 32-char Iterable key in JSON",
			src:  `{"iterable_api_key": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"}`,
			want: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := scanOne(t, "debug.json", tc.src)
			if fired := firedRule(got, "SEC-457"); fired != tc.want {
				t.Errorf("SEC-457 fired=%v want=%v (all: %s)", fired, tc.want, ruleIDs(got))
			}
		})
	}
}
