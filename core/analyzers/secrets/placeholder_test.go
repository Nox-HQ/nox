package secrets

import "testing"

// TestIsPlaceholderValue asserts the example/placeholder allowlist drops
// documentation defaults but keeps plausibly real credentials. The corpus's
// clean_placeholders.py / clean_env_example.py false positives are the
// motivating cases.
func TestIsPlaceholderValue(t *testing.T) {
	tests := []struct {
		name    string
		matched string
		want    bool
	}{
		// Placeholders that MUST be dropped.
		{"your-api-key-here", `your-api-key-here`, true},
		{"changeme", `changeme`, true},
		{"changeme in assignment", `PASSWORD = "changeme"`, true},
		{"all-x mask", `xxxxxxxxxxxxxxxxxxxxxxxx`, true},
		{"lowercase url user:password", `postgres://user:password@localhost:5432/db`, true},
		{"uppercase url template", `postgres://USER:PASSWORD@HOST:5432/DBNAME`, true},
		{"stripe test all-zero body", `sk_test_00000000000000000000000000`, true},
		{"angle bracket template", `<your-smtp-password>`, true},
		{"angle bracket in assignment", `SMTP_PASSWORD = "<your-smtp-password>"`, true},
		{"replace-me", `replace-me-with-a-real-secret`, true},
		{"example token", `example-secret-token`, true},

		// Real credentials that MUST be kept.
		{"real github pat", `ghp_016C7f8e9d0A1b2C3d4E5f6G7h8I9j0K1l2M`, false},
		{"real aws key", `AKIAIOSFODNN7EXAMPLE`, false}, // canonical AWS example still a valid shape; keep (AWS docs key)
		{"real slack token", `xoxb-1234567890-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx`, false},
		{"real stripe live", `sk_live_4eC39HqLyjWDarjtT1zdp7dcABCDEFGH1234`, false},
		{"real gcp key", `AIzaSyA1234567890abcdefghijklmnopqrstuv`, false},
		{"high-entropy hex", `9f86d081884c7d659a2feaa0c55ad015a3bf4f1b`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isPlaceholderValue(tt.matched); got != tt.want {
				t.Errorf("isPlaceholderValue(%q) = %v, want %v", tt.matched, got, tt.want)
			}
		})
	}
}
