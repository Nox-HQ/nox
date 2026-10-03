package secrets

import (
	"strings"
	"testing"
)

// The data-blob refiner drops a match inside a string literal longer than 96
// bytes, on the premise that "96 bytes comfortably clears the longest real
// credentials". Several credential formats are longer than that by
// definition, so their rules could never report one written in a Python, JS
// or TS string -- the place a hard-coded credential lives. JWTs were exempted
// for exactly this reason; the general fact is that a rule which anchors a
// vendor's format has established a credential, and a length heuristic for
// opaque payloads must not overrule it.

func blobBody(n int, alphabet string) string {
	var b strings.Builder
	x := uint32(88172645)
	for i := 0; i < n; i++ {
		x ^= x << 13
		x ^= x >> 17
		x ^= x << 5
		b.WriteByte(alphabet[int(x)%len(alphabet)])
	}
	return b.String()
}

const (
	b64url = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
	b64std = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	hexLow = "0123456789abcdef"
	upNum  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

func TestBlobRefiner_KeepsFormatAnchoredCredentialsInStrings(t *testing.T) {
	cases := []struct{ id, token string }{
		{"SEC-166", "sk-ant-" + "admin01-" + blobBody(93, b64url) + "AA"},
		{"SEC-169", "AB" + "SK" + blobBody(120, b64std)},
		{"SEC-350", "hv" + "b." + blobBody(150, b64url)},
		{"SEC-179", "v1" + ".0-" + blobBody(24, hexLow) + "-" + blobBody(146, hexLow)},
		{"SEC-326", "xoxe" + ".xoxb-1-" + blobBody(165, upNum)},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			src := "CREDENTIAL = \"" + tc.token + "\"\n"
			if len(tc.token) <= 96 {
				t.Fatalf("fixture is %d bytes; it must exceed the blob threshold to test anything", len(tc.token))
			}
			fs := scanOne(t, "settings.py", src)
			if !firedRule(fs, tc.id) {
				t.Errorf("%s did not report a %d-byte token in an ordinary string literal; findings: [%s]",
					tc.id, len(tc.token), ruleIDs(fs))
			}
		})
	}
}

// The threshold still does its job: a long, formatless base64 payload in a
// string is not reported by the loose and entropy rules.
func TestBlobRefiner_StillDropsOpaquePayloads(t *testing.T) {
	src := "ICON = \"" + blobBody(400, b64std) + "\"\n"
	if fs := scanOne(t, "icons.py", src); len(fs) != 0 {
		t.Errorf("an opaque base64 payload in a string was reported: [%s]", ruleIDs(fs))
	}
}
