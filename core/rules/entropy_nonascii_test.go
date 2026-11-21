package rules

import (
	"math/rand"
	"testing"
)

// Text in a script without spaces is not a secret. SEC-161 reported 7,512
// strings of random CJK characters in one mock-data file of the RealVuln
// benchmark (realvuln-jeecgboot, vxe/json/ddjh.json) as possible secrets:
// the quoted and assignment tokenizers accept any character, entropy counts
// runes, and the whitespace test that rejects prose never sees a space in
// Chinese or Japanese. A generated credential is printable ASCII in every
// encoding nox knows (base64, base64url, base58, base32, hex, prefixed tokens).
func TestEntropyMatcherSkipsNonASCIIText(t *testing.T) {
	t.Parallel()
	m := &EntropyMatcher{}
	rule := Rule{MatcherType: "entropy"}

	for name, line := range map[string]string{
		"cjk mock data": `"task_content": "港踡諙庁胯駦檰蔹癤承竩鯗釂厺逦裎藐英灕绣蠄栝餥垆藪澎寒尖鯏萟蘅森阮细"`,
		"cjk with key":  `secret: "鉹譌糶蘚禆奵糡绹櫴港踡諙庁胯駦檰蔹癤承竩鯗釂厺逦裎"`,
		"latin accents": `"note": "Grüße-aus-München-schöne-Straße-mit-Bäumen-überall"`,
	} {
		if got := m.Match([]byte(line), &rule); len(got) != 0 {
			t.Errorf("%s: reported %q as a possible secret", name, got[0].MatchText)
		}
	}
}

// The recall half: the check is on the candidate, not the line. A random ASCII
// key stays reported when a comment beside it is written in Japanese.
func TestEntropyMatcherKeepsASCIISecretBesideNonASCIIText(t *testing.T) {
	t.Parallel()
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	r := rand.New(rand.NewSource(161))
	key := make([]byte, 40)
	for i := range key {
		key[i] = alphabet[r.Intn(len(alphabet))]
	}
	line := `api_secret = "` + string(key) + `"  # 本番環境の鍵`

	m := &EntropyMatcher{}
	for _, res := range m.Match([]byte(line), &Rule{MatcherType: "entropy"}) {
		if res.MatchText == string(key) {
			return
		}
	}
	t.Fatalf("the ASCII key beside a Japanese comment is no longer reported: %s", line)
}
