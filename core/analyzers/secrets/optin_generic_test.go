package secrets

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/nox-hq/nox/core/discovery"
)

func scanWith(t *testing.T, a *Analyzer, name, src string) map[string]bool {
	t.Helper()
	abs := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(abs, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	fs, err := a.ScanArtifacts(context.Background(),
		[]discovery.Artifact{{Path: name, AbsPath: abs, Type: discovery.Source}})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, f := range fs.Findings() {
		got[f.RuleID] = true
	}
	return got
}

// SEC-951 is the generic "credential-named key, random-looking value" rule. The
// head-to-head found a GigaChat key (base64 of client_id:secret) and a
// MonsterAPI key (a UUID) only through gitleaks' generic rule, among 169
// findings, so it is opt-in: off unless scan.rules.enable names it. The values
// below are invented in the same shapes.
func TestSEC951IsOptIn(t *testing.T) {
	gigachat := `llm = GigaChatLLM(credentials="ZjNhOWMxZTItN2I0ZC00YzhhLTk1ZTEtMmQ2YjhmMGE0YzdlOmE4YjJjOTFkLTRlNWYtNDdhMS1iYzNkLTllOGYyYTFiNmM0ZA==")` + "\n"
	monster := `llm = MonsterLLM(api_key="7c2e9a41-3f8b-4d6e-a15c-9b0d2e7f4a83")` + "\n"

	off := NewAnalyzer()
	if scanWith(t, off, "a.py", gigachat)["SEC-951"] {
		t.Fatal("SEC-951 ran without being enabled")
	}

	on := NewAnalyzer()
	on.EnableOptIn([]string{"SEC-951"})
	for name, src := range map[string]string{"gigachat.py": gigachat, "monster.py": monster} {
		if !scanWith(t, on, name, src)["SEC-951"] {
			t.Errorf("%s: enabled SEC-951 did not report the value", name)
		}
	}
	for _, src := range []string{
		`api_key="your-api-key-here-please-change"`,
		`token="test-token-for-the-unit-tests"`,
		`secret: "0000000000000000000000000000"`,
		`api_key="ENVIRONMENT_VARIABLE_NAME_ONLY"`,
		// Words, not randomness: 115 of SEC-951's 137 findings on the
		// seven benchmark repositories were values like these.
		`AI_GATEWAY_API_KEY: 'sandbox-gateway-secret'`,
		`apiKey: 'anthropic-api-key'`,
		`api_key = "my-anthropic-api-key"`,
		`PROVIDER_API_KEY: 'ephemeral-PROVIDER_API_KEY'`,
		`envOidcToken: 'valid-oidc-token-12345'`,
	} {
		if scanWith(t, on, "c.py", src+"\n")["SEC-951"] {
			t.Errorf("enabled SEC-951 reported a placeholder: %s", src)
		}
	}
}
