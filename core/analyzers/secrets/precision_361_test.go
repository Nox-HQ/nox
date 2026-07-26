package secrets

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/findings"
)

// scanOne runs the full ScanArtifacts pipeline (not the bare engine) over a
// single in-memory file. The post-filters that decide these cases live in
// ScanArtifacts, so a ScanFile-based test would not exercise them.
func scanOne(t *testing.T, name, src string) []findings.Finding {
	t.Helper()
	dir := t.TempDir()
	abs := filepath.Join(dir, name)
	if err := os.WriteFile(abs, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	fs, err := NewAnalyzer().ScanArtifacts(context.Background(),
		[]discovery.Artifact{{Path: name, AbsPath: abs, Type: discovery.Source}})
	if err != nil {
		t.Fatal(err)
	}
	return fs.Findings()
}

func firedRule(f []findings.Finding, id string) bool {
	for i := range f {
		if f[i].RuleID == id {
			return true
		}
	}
	return false
}

func ruleIDs(f []findings.Finding) string {
	var ids []string
	for i := range f {
		ids = append(ids, f[i].RuleID)
	}
	return strings.Join(ids, ",")
}

// TestProviderPrefixNeedsLeftWordBoundary covers the class where a provider
// key prefix is matched in the MIDDLE of an ordinary identifier.
//
// `TestSessionStore_LoadsLegacySnapshotWithoutSchemaField` contains `re_` at the
// seam of `Store_Loads`, and 38 alphanumerics follow it, so the Resend rule
// reported a high-severity API key on a Go test function name. The same seam
// exists for the GitHub rules: `TestProcessHighs_Lows…` contains `ghs_`.
//
// A credential is never glued to the tail of a preceding word, so requiring a
// word boundary on the left removes the whole class. The second half of each
// case is the regression guard: a real key, which always begins at a boundary
// (after a quote, an `=`, or whitespace), must still be reported.
func TestProviderPrefixNeedsLeftWordBoundary(t *testing.T) {
	cases := []struct {
		name string
		rule string
		src  string
		want bool
	}{
		{
			name: "resend prefix inside a Go identifier",
			rule: "SEC-147",
			src:  "package p\n\nfunc TestSessionStore_LoadsLegacySnapshotWithoutSchemaField(t *testing.T) {}\n",
			want: false,
		},
		{
			name: "real resend key in a Go string",
			rule: "SEC-147",
			src:  "package p\n\nvar k = \"re_2xKq7ZmT4bWvR8nHs5LpYd3JcF6gAe1U\"\n",
			want: true,
		},
		{
			name: "github app prefix inside a Go identifier",
			rule: "SEC-003",
			src:  "package p\n\nfunc TestProcessHighs_LowsAcrossTheWholeWindowDeterministic(t *testing.T) {}\n",
			want: false,
		},
		{
			name: "real github token in a Go string",
			rule: "SEC-003",
			src:  "package p\n\nvar k = \"ghs_16C7e42F292c6912E7710c838347Ae178B4a\"\n",
			want: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := scanOne(t, "store_test.go", tc.src)
			if fired := firedRule(got, tc.rule); fired != tc.want {
				t.Errorf("%s fired=%v want=%v (all: %s)", tc.rule, fired, tc.want, ruleIDs(got))
			}
		})
	}
}

// TestGitHubTokenRuleRequiresIssuedShape covers SEC-435, whose pattern required
// a `gh[pousr]_` prefix and exactly ONE further character. Any five-character
// run beginning `ghs_` was a high-severity "Detected GitHub Token" — including
// the string literal `"ghs_fake_install_token"` in a _test.go file, which is
// not a shape GitHub ever issues (its tokens are 36 alphanumerics, never
// underscores).
//
// The rule contributed no unique detection: every well-formed GitHub token it
// could catch is already caught by SEC-003/SEC-213/SEC-215/SEC-216/SEC-217, so
// giving it the issued shape costs no recall.
//
// The guards assert both halves of that: the rule itself still matches an
// issued token (at the engine, since specificity dedup then collapses it into
// SEC-003), and the token is still REPORTED end to end.
func TestGitHubTokenRuleRequiresIssuedShape(t *testing.T) {
	const fixture = "package p\n\n// github installation token exchange\nfunc TestAuth(tok string) bool { return tok != \"ghs_fake_install_token\" }\n"
	const issued = "package p\n\n// github\nvar tok = \"ghs_16C7e42F292c6912E7710c838347Ae178B4a\"\n"

	t.Run("test fixture that is not an issued token shape", func(t *testing.T) {
		got := scanOne(t, "auth_test.go", fixture)
		if firedRule(got, "SEC-435") {
			t.Errorf("SEC-435 fired on a literal named fake (all: %s)", ruleIDs(got))
		}
	})

	t.Run("rule still matches an issued token", func(t *testing.T) {
		got, err := NewAnalyzer().ScanFile("auth.go", []byte(issued))
		if err != nil {
			t.Fatal(err)
		}
		if !firedRule(got, "SEC-435") {
			t.Errorf("SEC-435 must still match an issued GitHub token (all: %s)", ruleIDs(got))
		}
	})

	t.Run("issued token is still reported end to end", func(t *testing.T) {
		got := scanOne(t, "auth.go", issued)
		if len(got) == 0 {
			t.Error("an issued GitHub token must still be reported, got no findings")
		}
	})
}

// TestPrivateKeyHeaderInDisplayAttribute covers SEC-004 firing critical on
//
//	<input placeholder="-----BEGIN RSA PRIVATE KEY-----…" />
//
// A `placeholder` attribute is the text shown to a user in an empty field. It
// tells the operator what to paste; the key material is theirs and arrives at
// runtime. No secret is present in the repository, yet this was a CRITICAL
// finding — the band the shared CI gate fails on.
//
// The guard cases assert the rule still fires on key material that is genuinely
// in the tree, including in an ordinary attribute such as `value=`.
func TestPrivateKeyHeaderInDisplayAttribute(t *testing.T) {
	cases := []struct {
		name string
		file string
		src  string
		want bool
	}{
		{
			name: "jsx placeholder attribute",
			file: "ui.tsx",
			src:  "export const K = () => (\n  <input placeholder=\"-----BEGIN RSA PRIVATE KEY-----&#10;...&#10;-----END RSA PRIVATE KEY-----\" />\n);\n",
			want: false,
		},
		{
			name: "html aria-label attribute",
			file: "form.html",
			src:  "<textarea aria-label=\"-----BEGIN OPENSSH PRIVATE KEY----- goes here\"></textarea>\n",
			want: false,
		},
		{
			name: "real private key in a Go source constant",
			file: "key.go",
			src:  "package p\n\nconst k = `-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----`\n",
			want: true,
		},
		{
			name: "private key pasted into a value attribute",
			file: "ui.tsx",
			src:  "export const K = () => (\n  <input value=\"-----BEGIN RSA PRIVATE KEY-----\" />\n);\n",
			want: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := scanOne(t, tc.file, tc.src)
			if fired := firedRule(got, "SEC-004"); fired != tc.want {
				t.Errorf("SEC-004 fired=%v want=%v (all: %s)", fired, tc.want, ruleIDs(got))
			}
		})
	}
}

// TestConfigFieldRuleNotMatchedInProse covers SEC-240, the Gitleaks-imported
// HashiCorp Terraform password-field rule, firing high on a Go doc comment:
//
//	// "bot_token" pops a password input, "imap_password" pops an app-password wizard.
//
// The rule infers a credential from a `field <separator> "value"` shape. Its
// separator alternation includes `,`, so the prose above parses as
// `password …` `,` `"imap_password"`. There is no assignment in a comment —
// there is prose describing one — so the inference cannot hold.
//
// The guards are the two ways this must NOT become a false negative: the same
// rule on a genuine Terraform assignment, and a credential a developer really
// did leave in a comment (still reported, by the generic keyword rule).
func TestConfigFieldRuleNotMatchedInProse(t *testing.T) {
	t.Run("terraform password rule on a Go doc comment", func(t *testing.T) {
		src := "package p\n\n// Fields render by name:\n// \"bot_token\" pops a password input, \"imap_password\" pops an app-password wizard.\nfunc Manifest() {}\n"
		got := scanOne(t, "manifest.go", src)
		if firedRule(got, "SEC-240") {
			t.Errorf("SEC-240 fired on a Go doc comment (all: %s)", ruleIDs(got))
		}
	})

	t.Run("terraform password rule on a real assignment", func(t *testing.T) {
		src := "resource \"azurerm_mssql_server\" \"x\" {\n  administrator_login_password = \"h7Qz2LmXk9Ta\"\n}\n"
		got := scanOne(t, "main.tf", src)
		if !firedRule(got, "SEC-240") {
			t.Errorf("SEC-240 must still fire on a Terraform password assignment (all: %s)", ruleIDs(got))
		}
	})

	t.Run("credential genuinely left in a comment is still reported", func(t *testing.T) {
		for _, tc := range []struct{ file, src string }{
			{"app.go", "package p\n\n// password = \"h7Qz2LmXk9Ta\"\nfunc M() {}\n"},
			{"vals.yaml", "# password: \"h7Qz2LmXk9Ta\"\n"},
		} {
			got := scanOne(t, tc.file, tc.src)
			if len(got) == 0 {
				t.Errorf("%s: a credential leaked in a comment must still be reported, got none", tc.file)
			}
		}
	})
}
