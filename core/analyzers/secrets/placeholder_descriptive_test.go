package secrets

import "testing"

// Values that describe themselves instead of being random. Every "drop" case
// is a line from the 2026-09-27 head-to-head benchmark, where these four
// keyword rules (SEC-080/082/801/803) produced most of nox's secret noise:
// `test-api-key` alone was 86 lines. Every "keep" case is something a
// placeholder check must never swallow.
func TestDescriptiveValuesArePlaceholders(t *testing.T) {
	drop := []string{
		`Authorization: 'Bearer test-api-key'`,
		`authorization: 'Bearer mock-auth-token'`,
		`Authorization: 'Bearer test-api-key-789'`,
		`authorization: 'Bearer TEST_TOKEN'`,
		`Authorization: 'Bearer token-2'`,
		`authorization: 'Bearer sk-test'`,
		`password="test_password"`,
		`password="test_pass"`,
		`password="my_password"`,
		`OPENAI_API_KEY=sua_chave_openai`,
		`ANTHROPIC_API_KEY=sua_chave_anthropic`,
		`OPENAI_API_KEY=tu_clave_openai`,
		`OPENROUTER_API_KEY=fake-openrouter-key`,
		`ANTHROPIC_API_KEY: 'fake-anthropic-key`,
		`access_token: 'expired-access-token'`,
		`OPENAI_API_KEY: 'my-api-key`,
		// From llama_index notebooks, reachable since #732 scans them.
		`password="PASTE YOUR PASSWORD HERE"`,
		`password="FakeExamplePassword"`,
	}
	keep := []string{
		`Authorization: 'Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U'`,
		`OPENAI_API_KEY=sk-proj-4f9Qx2LmZr8TtKp1Vw7Yb3Nc6Hd0Ja5Ue`,
		`sk_test_51H8qX2LmZr8TtKp1Vw7Yb3Nc6Hd0Ja5UeRq`, // a Stripe test-mode key is still a key
		`password="hunter2"`,
		`password="correct-horse-battery-staple"`, // a passphrase: words, but no marker
		`password="OXYLABS_PASSWORD"`,
		`Authorization: 'Bearer gateway-secret'`,
		`password="CorrectHorseBatteryStaple"`, // CamelCase words, no marker
		`password="yourcompanyadmin2024"`,      // "your" inside a word is not the word
	}
	for _, v := range drop {
		if !isPlaceholderValue(v) {
			t.Errorf("isPlaceholderValue(%q) = false, want true", v)
		}
	}
	for _, v := range keep {
		if isPlaceholderValue(v) {
			t.Errorf("isPlaceholderValue(%q) = true, want false", v)
		}
	}
}
