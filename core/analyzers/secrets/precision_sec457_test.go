package secrets

import "testing"

// SEC-457 (Iterable API key) fired on 40-character git SHAs.
//
// princeton-nlp/SWE-agent's debug_20240322.json carries values like
// `"commit": "953f29f700a60fc09b08b2c2270c12c447490c6a"`, and the rule's bare
// `[a-z0-9]{32}` matched the first 32 characters of the 40-char hex — 18
// high-severity false positives in one file, every time the word "iterable"
// appeared anywhere in it, which in Python is typing.Iterable.
//
// The same class was measured again later on anthropic-sdk-python: 11 findings,
// all git SHAs in CHANGELOG.md, licensed by "iterabl(es)" up to 180 characters
// away on the same physical line.
//
// It is fixed by binding rather than by word boundaries. SEC-457 is in the
// vendor-bound family now (rules.SubjectKindKey's neighbour, `vendor_bound`),
// so the pattern requires the vendor name to BIND the value —
// `iterable… = "<32>"` — and a SHA in a changelog or a JSON commit field has no
// such binding whatever its length.
//
// This test is salvaged from PR #557, which proposed the word-boundary fix
// before the family fix existed. The fix it carried is superseded; the case it
// documents is not, and this fails loudly if the family is ever unbound.
func TestSEC457DoesNotMatchAGitSHA(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		src  string
		want bool
	}{
		{
			name: "40-char git SHA in JSON, with an iterable-ish key in the same object",
			src:  `{"iterable_cursor": null, "commit": "953f29f700a60fc09b08b2c2270c12c447490c6a"}`,
			want: false,
		},
		{
			name: "a real Iterable key, bound to its vendor's name",
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
