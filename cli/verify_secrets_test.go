package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A detected secret and a LIVE secret are different findings. "This looks like
// a GitHub token" is a backlog item; "this is a working GitHub token for user
// X" is an incident. Only the issuer can tell them apart, and the check needs
// no privilege beyond the leaked credential itself.
//
// nox deliberately does not keep the secret in findings.json — a finding
// carries only a file and column range — so verification re-reads the file at
// the recorded location. That keeps findings.json shareable, which is a
// property worth not losing.

func TestExtractSecretAtLocation(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "cfg.go")
	body := "package main\n\nconst tok = \"ghp_" + strings.Repeat("A", 36) + "\"\n"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	// Columns as the secrets analyzer reports them: 1-based within the LINE,
	// end exclusive. Verified against a real finding: an AKIA key alone on a
	// line reports StartColumn 1, EndColumn 21 for 20 characters.
	line3 := strings.Split(body, "\n")[2]
	start := strings.Index(line3, "ghp_") + 1
	got, err := extractSecretAt(p, 3, start, start+40)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if got != "ghp_"+strings.Repeat("A", 36) {
		t.Errorf("extracted %q, want the token literal", got)
	}
}

// A finding whose location no longer matches the file — because the secret was
// removed, or the scan is stale — must not silently verify whatever text now
// occupies those columns.
func TestExtractSecretAtLocation_OutOfRange(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "small.txt")
	if err := os.WriteFile(p, []byte("short\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := extractSecretAt(p, 99, 1, 40); err == nil {
		t.Error("a line past end-of-file produced no error")
	}
	if _, err := extractSecretAt(p, 1, 1, 400); err == nil {
		t.Error("a column past end-of-line produced no error")
	}
}

// THE security property of this feature. Verification transmits a live
// credential to a third party, which is only defensible when that party is the
// issuer. If the endpoint were configurable, `--verify-secrets` would be an
// exfiltration primitive built into a security scanner: point it at a host you
// control and every secret in the repo is delivered to you.
//
// So endpoints are compiled in, per provider, and there is no flag, config key
// or environment variable that redirects them.
func TestVerifierEndpointsAreNotConfigurable(t *testing.T) {
	src, err := os.ReadFile("verify_secrets.go")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	text := string(src)

	for _, forbidden := range []string{
		"os.Getenv", "flag.String", "cfg.", "Endpoint =", "baseURL =",
	} {
		if strings.Contains(text, forbidden) {
			t.Errorf("verify_secrets.go contains %q — the verification endpoint must not be "+
				"redirectable, or this becomes a way to exfiltrate every secret in the repo", forbidden)
		}
	}
	// Each provider's host must appear as a literal.
	for _, host := range []string{"api.github.com"} {
		if !strings.Contains(text, host) {
			t.Errorf("no compiled-in endpoint for %s", host)
		}
	}
}

func TestVerifyGitHubToken(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		want   validity
	}{
		{"live token", http.StatusOK, `{"login":"octocat"}`, validityLive},
		{"revoked token", http.StatusUnauthorized, `{"message":"Bad credentials"}`, validityDead},
		// Rate limiting is not evidence either way. Reporting "dead" here would
		// tell someone a live credential is safe to ignore.
		{"rate limited", http.StatusForbidden, `{"message":"rate limit"}`, validityUnknown},
		{"server error", http.StatusInternalServerError, ``, validityUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if got := r.Header.Get("Authorization"); got != "Bearer ghp_test" {
					t.Errorf("Authorization = %q, want the token as a bearer credential", got)
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			got, _ := verifyGitHubToken("ghp_test", srv.URL)
			if got != tc.want {
				t.Errorf("validity = %v, want %v", got, tc.want)
			}
		})
	}
}

// A live credential must never reach a log line, a finding message, or stdout.
// The whole point is to report that a secret works, not to reproduce it.
func TestVerificationOutputNeverContainsTheSecret(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"login":"octocat"}`))
	}))
	defer srv.Close()

	secret := "ghp_" + strings.Repeat("S", 36)
	_, detail := verifyGitHubToken(secret, srv.URL)
	if strings.Contains(detail, secret) {
		t.Errorf("the verification detail echoes the secret: %q", detail)
	}
	if strings.Contains(detail, "ghp_SSSS") {
		t.Errorf("the detail contains a recognisable prefix of the secret: %q", detail)
	}
}
