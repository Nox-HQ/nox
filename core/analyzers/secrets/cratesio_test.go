package secrets

import (
	"strings"
	"testing"
)

// crates.io issues "cio" + exactly 32 alphanumerics (TOKEN_PREFIX and
// TOKEN_LENGTH in crates_io_database/src/utils/token.rs). SEC-055 required 36
// or more after the prefix, so it could not report a single real token while
// firing on every "cio" inside a base64 run (#930).
func TestSEC055MatchesTheCratesIOTokenFormat(t *testing.T) {
	token := "cio" + strings.Repeat("Ab3De5Fg7H", 4)[:32]
	if !reports(t, ".env", "CARGO_REGISTRY_TOKEN="+token+"\n", "SEC-055") {
		t.Error("a crates.io token (cio + 32) is not reported")
	}
	// Inside a longer alphanumeric run it is not a token: the run continues
	// past where a crates.io token ends, and begins before "cio".
	if reports(t, "blob.txt", "x = Zq"+token+"Qz9\n", "SEC-055") {
		t.Error("a cio window inside a longer run is reported as a crates.io token")
	}
}
