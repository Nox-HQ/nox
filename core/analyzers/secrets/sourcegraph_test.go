package secrets

import (
	"encoding/hex"
	"math/rand"
	"slices"
	"testing"
)

// SEC-335 is Sourcegraph's access token. Its gitleaks import carried a third
// alternative, a bare [a-f0-9]{40}, gated only by the file keyword
// `sourcegraph`. Forty hex digits is also a git object name and a SHA-1 ETag,
// so a README that says "we index with Sourcegraph" and pins a commit was a
// high-severity credential finding. That is the pre-v1.36 CSP/ETag
// construction, in a rule the v1.36 binding pass did not reach because its
// pattern is not anchorless. Found by the concrete-witness research (#814).
//
// The legacy form is real -- Sourcegraph generates 20 random bytes, hex
// encoded, and tokens issued before 5.1.0 carry no prefix and still work -- so
// the fix binds it to a credential name rather than dropping it.

// sgHex draws n hex digits from a seeded RNG: a hand-typed "random" value is
// the thing a placeholder filter is built to recognise.
func sgHex(seed int64, n int) string {
	b := make([]byte, (n+1)/2)
	rand.New(rand.NewSource(seed)).Read(b)
	return hex.EncodeToString(b)[:n]
}

func TestSourcegraphBareHexIsNotACredential(t *testing.T) {
	sha := sgHex(335, 40)
	for _, tc := range []struct{ name, path, body string }{
		{"pinned commit in a README", "README.md",
			"# Code search\n\nWe index with Sourcegraph. Pinned to upstream commit " + sha + " for reproducibility.\n"},
		{"SHA-pinned action", "ci.yml",
			"steps:\n  - uses: actions/checkout@" + sha + " # sourcegraph indexer\n"},
		{"ETag below a CSP naming sourcegraph.com", "response.txt",
			"HTTP/2 200\ncontent-security-policy: connect-src https://sourcegraph.com\netag: \"" + sha + "\"\n"},
		{"commit field beside a sourcegraph setting", "config.yaml",
			"sourcegraph_url: https://sourcegraph.example.com\nsourcegraph_commit: " + sha + "\n"},
	} {
		if got := idsFor(t, tc.path, tc.body); slices.Contains(got, "SEC-335") {
			t.Errorf("%s: SEC-335 reports a 40-hex value that is not a credential\n%s", tc.name, tc.body)
		}
	}
}

func TestSourcegraphTokensAreReported(t *testing.T) {
	legacy := sgHex(536, 40)
	for _, tc := range []struct{ name, path, body string }{
		// src-cli's environment variable, with a token issued before 5.1.0.
		{"legacy token in SRC_ACCESS_TOKEN", "env.sh", "export SRC_ACCESS_TOKEN=" + legacy + "\n"},
		{"legacy token bound to a sourcegraph token name", "config.yaml", "sourcegraph_token: " + legacy + "\n"},
		{"legacy token, quoted assignment", "settings.py", `SOURCEGRAPH_ACCESS_TOKEN = "` + legacy + `"` + "\n"},
		{"sgp_ prefixed legacy body", "notes.md", "token sgp_" + legacy + " was revoked\n"},
		{"sgp_ with instance id", "notes.md", "token sgp_" + sgHex(7, 16) + "_" + sgHex(8, 40) + " was revoked\n"},
		{"sgp_ dev instance", "notes.md", "token sgp_local_" + sgHex(9, 40) + " was revoked\n"},
	} {
		if got := idsFor(t, tc.path, tc.body); !slices.Contains(got, "SEC-335") {
			t.Errorf("%s: SEC-335 does not report a Sourcegraph token\n%s   ids=%v", tc.name, tc.body, got)
		}
	}
}
