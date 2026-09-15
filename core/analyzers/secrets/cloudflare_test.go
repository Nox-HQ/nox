package secrets

import (
	"slices"
	"strings"
	"testing"
)

// SEC-446 held `[a-zA-Z0-9_-]{37,43}` gated on the word "cloudflare".
//
// Recorded HTTP cassettes carry a `server: cloudflare` header, so the keyword
// is legitimately present in every one of them and whole-token matching does
// not help. Every 37-43 character run in the response then inherits it. 228
// findings on the pinned corpus: 201 `__cf_bm` / `_cfuvid` bot-management
// cookies, the rest NEL endpoints and CHANGELOG package names. Zero credentials.
//
// Cloudflare's documented formats (fundamentals/api/get-started/token-formats):
//
//	cfk_  + 40 + checksum   Global API Key
//	cfut_ + 40 + checksum   User API Token
//	cfat_ + 40 + checksum   Account API Token
//	legacy Global API Key   37-45 lowercase hex, no prefix
//	legacy API tokens       40 alphanumeric, no prefix -- SEC-087's shape
//
// So the rule is bound two ways: the prefixed forms identify themselves, and
// the legacy global key is reached through a Cloudflare-specific assignment.

func fired(t *testing.T, body string) []string {
	t.Helper()
	a := NewAnalyzer()
	found, err := a.ScanFile("config.yml", []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	out := make([]string, 0, len(found))
	for _, f := range found {
		out = append(out, f.RuleID)
	}
	return out
}

func TestSEC446ReportsCloudflareCredentials(t *testing.T) {
	forty := strings.Repeat("a1B2c3D4e5", 4) // 40 alphanumeric
	for name, line := range map[string]string{
		"global api key (cfk_)":     `key = "cfk_` + forty + `xyz"`,
		"user api token (cfut_)":    `tok = "cfut_` + forty + `xyz"`,
		"account api token (cfat_)": `tok = "cfat_` + forty + `xyz"`,
		"legacy global key, bound":  `cloudflare_api_key = "` + strings.Repeat("0a1b2c3d4e", 4) + `5f6"`,
	} {
		if !slices.Contains(fired(t, "# cloudflare\n"+line+"\n"), "SEC-446") {
			t.Errorf("SEC-446 does not report the %s: %s", name, line)
		}
	}
}

// TestSEC446IgnoresTheBotCookie is the 201-finding false-positive class. A
// `__cf_bm` value is base64url -- uppercase, dots and hyphens -- so it cannot
// satisfy the lowercase-hex legacy form, and it carries no prefix.
func TestSEC446IgnoresTheBotCookie(t *testing.T) {
	for _, line := range []string{
		`- __cf_bm=8J2Cz0gyk5BpRSYbzjWETqMiyphlW8TAe7802MlHMe0-1745770077-1.0.1.1-qbyKIgJQJDS2wWD`,
		`- _cfuvid=LMbhtXYRu2foKMlmDSxZF0LlpAWtafPdjq_4PWulGz0-1747825944424-0.0.1.1-604800000`,
		`### llama-index-embeddings-cloudflare-workersai [0.5.0]`,
		`{"group":"cf-nel","endpoints":[{"url":"https://a.nel.cloudflare.com/report"}]}`,
	} {
		body := "server: cloudflare\n" + line + "\n"
		if slices.Contains(fired(t, body), "SEC-446") {
			t.Errorf("SEC-446 still fires on a non-credential near the word cloudflare: %s", line)
		}
	}
}

// TestSEC446AndSEC087DoNotOverlap. The user-facing reason to keep both is that
// they report different credentials; if one is a subset of the other, the pair
// should be merged. SEC-087 owns the legacy 40-character API TOKEN assignment,
// SEC-446 the prefixed forms and the legacy hex GLOBAL KEY.
func TestSEC446AndSEC087DoNotOverlap(t *testing.T) {
	legacyToken := `cloudflare_api_token = "` + strings.Repeat("a1B2c3D4e5", 4) + `"`
	ids := fired(t, "# cloudflare\n"+legacyToken+"\n")
	if !slices.Contains(ids, "SEC-087") {
		t.Errorf("SEC-087 no longer reports the legacy API token assignment; ids=%v", ids)
	}
	if slices.Contains(ids, "SEC-446") {
		t.Error("SEC-446 also reports SEC-087's legacy token assignment: the two overlap, " +
			"and an operator fixes one condition and sees it twice")
	}
	globalKey := `cloudflare_api_key = "` + strings.Repeat("0a1b2c3d4e", 4) + `5f6"`
	ids = fired(t, "# cloudflare\n"+globalKey+"\n")
	if !slices.Contains(ids, "SEC-446") {
		t.Errorf("SEC-446 does not report the legacy global API key; ids=%v", ids)
	}
	if slices.Contains(ids, "SEC-087") {
		t.Error("SEC-087 reports the global API key too; the split between the two rules " +
			"is not the one their descriptions claim")
	}
}
