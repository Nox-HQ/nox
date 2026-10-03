package rules

import (
	"math/rand"
	"testing"
)

// isCamelOrPascalCase was meant to recognise identifiers -- getUserName,
// NewJSONReporter -- and excuse them from secret-shape checks. Its test was
// "letters and digits only, a lowercase-to-uppercase transition, at most 20%
// digits". A uniformly random base62 credential averages 10/62 = 16% digits and
// almost always has such a transition, so it passed that test too: measured,
// 66-82% of random 16-40 character tokens were rejected as "camelCase
// identifiers", and every rule behind the secret-shape filter dropped most real
// random credentials it had correctly bound. The hand-typed fixtures never
// showed it, because people typing a "random" key overweight digits.
//
// What separates the two is word structure: an identifier is made of lowercase
// runs ("Invalid", "Reporter"), random text is not (mean lowercase run ~1.7).

func randomTokens(seed int64, n, length int) []string {
	const b62 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	rng := rand.New(rand.NewSource(seed))
	out := make([]string, n)
	for i := range out {
		b := make([]byte, length)
		for j := range b {
			b[j] = b62[rng.Intn(len(b62))]
		}
		out[i] = string(b)
	}
	return out
}

func TestRandomTokensAreNotCamelCase(t *testing.T) {
	for _, length := range []int{16, 20, 24, 32, 40} {
		toks := randomTokens(int64(length), 5000, length)
		rejected := 0
		for _, s := range toks {
			if isCamelOrPascalCase(s) {
				rejected++
			}
		}
		// The measured rate after the fix is 4-9.5%; the bound leaves room
		// for the sample, and is far from the 66-82% this replaced.
		if frac := float64(rejected) / float64(len(toks)); frac > 0.12 {
			t.Errorf("length %d: %.1f%% of uniformly random tokens classified as camelCase identifiers",
				length, 100*frac)
		}
	}
}

func TestIdentifiersAreStillCamelCase(t *testing.T) {
	for _, id := range []string{
		"getUserAccountName", "resolvedOptionsThreadKey", "NewJSONReporter",
		"MCPClientOAuthError", "TestInvalidJSON", "isLoadAPIKeyError",
		"JSONRPCNotificationSchema", "VulnLDAPInjection", "cycloneDXBOM",
		"SetMaxIdleConns", "ErrTaskNotFound", "maxRetryBackoffSeconds",
	} {
		if !isCamelOrPascalCase(id) {
			t.Errorf("%s is an identifier and must still be classified as one", id)
		}
	}
}
