package secrets

import (
	"strings"
	"testing"
)

// Recorded model API traffic carries ciphertext the provider issues and takes
// back: Anthropic's thinking-block "signature" and web-search
// "encrypted_index", OpenAI's reasoning "encrypted_content", Gemini's
// "thoughtSignature". Long base64 runs, so the entropy rule and short-prefix
// vendor rules fired inside them: 67 findings on the 2026-09-27 head-to-head.
func TestModelIssuedCiphertextIsNotACredential(t *testing.T) {
	token := "oy2" + strings.Repeat("aB3dE5fG7h", 5)[:43] // SEC-048's shape
	blob := "EvYBCkgICxABGAIqQA9E9VC377UnbjdfXCw4RwQaaIXsqocZKzI3WwWtXT" + token + "wBjzAkBOfIiVkP"
	for _, key := range []string{"signature", "thoughtSignature", "encrypted_content", "encrypted_index"} {
		src := "{\"type\": \"thinking\", \"" + key + "\": \"" + blob + "\"}\n"
		if reports(t, "fixture.json", src, "SEC-048") {
			t.Errorf("%q: SEC-048 reported inside model-issued ciphertext", key)
		}
	}

	// The same token under any other key is still a NuGet key.
	if !reports(t, "fixture.json", "{\"nuget_api_key\": \""+token+"\"}\n", "SEC-048") {
		t.Error("a NuGet key under an ordinary key is no longer reported")
	}
}
