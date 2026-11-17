package secrets

import (
	"math/rand"
	"testing"
)

func TestIsLocaleCatalogue(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"web/src/locales/de.ts", true},
		{"web/src/locales/zh-traditional.ts", true},
		{"web/src/locales/pt-br.ts", true},
		{"src/i18n/en/common.json", true},
		{"config/lang/pt_BR.properties", true},
		{`app\locales\fr.json`, true},
		// A locale directory also holds code.
		{"web/src/locales/index.ts", false},
		{"src/i18n/config.ts", false},
		// A language-named file outside a locale directory is not one.
		{"de.ts", false},
		{"conf/service_conf.yaml", false},
		{"src/lang/parser.go", false},
		{"locales/de/nested/more.json", false},
		{"locales/de.go", false},
	}
	for _, tt := range tests {
		if got := isLocaleCatalogue(tt.path); got != tt.want {
			t.Errorf("isLocaleCatalogue(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

// seededPassword is a password-shaped value no rule has seen, generated rather
// than written by hand so the test cannot be tuned to the rule.
func seededPassword() string {
	const alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!#%&*"
	r := rand.New(rand.NewSource(1096))
	b := make([]byte, 14)
	for i := range b {
		b[i] = alphabet[r.Intn(len(alphabet))]
	}
	return string(b)
}

func localeRuleIDs(t *testing.T, name, body string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, f := range scanAt(t, name, body) {
		out[f.RuleID] = true
	}
	return out
}

// TestSEC080TranslationLabelsAreNotPasswords is RAGFlow's case: one finding
// per language per password label.
func TestSEC080TranslationLabelsAreNotPasswords(t *testing.T) {
	body := "export default {\n  setting: {\n    password: 'Passwort',\n    confirmPassword: 'Neues Passwort bestätigen',\n  },\n};\n"
	if localeRuleIDs(t, "web/src/locales/de.ts", body)["SEC-080"] {
		t.Fatal("SEC-080 reported a translated form label in a locale catalogue as a password")
	}
}

// TestSEC080StillReportsRealPasswords is the half that makes the gate safe:
// the same assignment outside a catalogue, and in code that lives beside the
// catalogues, is still a hardcoded password.
func TestSEC080StillReportsRealPasswords(t *testing.T) {
	pw := seededPassword()
	cases := []struct{ name, path, body string }{
		{"config file", "conf/service_conf.yaml", "mysql:\n  password: '" + pw + "'\n"},
		{"code in a locale directory", "web/src/locales/index.ts", "export const db = { password: '" + pw + "' };\n"},
		{"language-named file outside a locale directory", "src/de.ts", "export const db = { password: '" + pw + "' };\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if !localeRuleIDs(t, c.path, c.body)["SEC-080"] {
				t.Fatalf("SEC-080 did not report a hardcoded password in %s", c.path)
			}
		})
	}
}
