package pypipin

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// An exact pin in a requirements file is moved by editing that pin, and
// nothing else on the line or in the file changes.
func TestExactPinIsEditedInPlace(t *testing.T) {
	cases := map[string]struct{ in, want string }{
		"plain":           {"requests==2.31.0\n", "requests==2.32.0\n"},
		"extras":          {"requests[socks]==2.31.0\n", "requests[socks]==2.32.0\n"},
		"marker":          {"requests==2.31.0 ; python_version >= \"3.8\"\n", "requests==2.32.0 ; python_version >= \"3.8\"\n"},
		"comment":         {"requests==2.31.0  # http client\n", "requests==2.32.0  # http client\n"},
		"spaces":          {"requests == 2.31.0\n", "requests == 2.32.0\n"},
		"normalized name": {"Requests==2.31.0\n", "Requests==2.32.0\n"},
		"only that line":  {"flask==3.0.0\nrequests==2.31.0\nidna==3.6\n", "flask==3.0.0\nrequests==2.32.0\nidna==3.6\n"},
		"crlf kept":       {"flask==3.0.0\r\nrequests==2.31.0\r\n", "flask==3.0.0\r\nrequests==2.32.0\r\n"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			p := write(t, "requirements.txt", tc.in)
			adv := AdviceFor(p, "requests", "2.31.0", "2.32.0")
			if adv.Command == "" || adv.Manual != "" {
				t.Fatalf("not editable: %+v", adv)
			}
			if err := adv.Apply(); err != nil {
				t.Fatal(err)
			}
			got, _ := os.ReadFile(p)
			if string(got) != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// Names compare as PEP 503 normalizes them: case, and runs of - _ . alike.
func TestNamesAreNormalized(t *testing.T) {
	p := write(t, "requirements.txt", "Typing_Extensions==4.7.0\n")
	if adv := AdviceFor(p, "typing-extensions", "4.7.0", "4.12.0"); adv.Command == "" {
		t.Fatalf("typing-extensions did not match Typing_Extensions: %+v", adv)
	}
	p = write(t, "requirements.txt", "requests-oauthlib==1.3.0\n")
	if adv := AdviceFor(p, "requests", "1.3.0", "2.32.0"); adv.Command != "" {
		t.Errorf("requests matched requests-oauthlib: %+v", adv)
	}
}

// What a pin edit cannot honestly do is manual, with no command and a reason.
func TestWhatCannotBeEditedIsManual(t *testing.T) {
	cases := map[string]struct {
		file, body, why string
	}{
		"range":          {"requirements.txt", "requests>=2.31.0\n", "not an exact pin"},
		"compound":       {"requirements.txt", "requests==2.31.0,!=2.31.1\n", "not an exact pin"},
		"hashed":         {"requirements.txt", "requests==2.31.0 \\\n    --hash=sha256:abc\n", "hash"},
		"require-hashes": {"requirements.txt", "--require-hashes\nrequests==2.31.0\n", "hash"},
		"other version":  {"requirements.txt", "requests==2.30.0\n", "2.31.0"},
		"absent":         {"requirements.txt", "flask==3.0.0\n", "not pinned"},
		"uv":             {"uv.lock", "version = 1\n", "uv lock --upgrade-package requests"},
		"poetry":         {"poetry.lock", "", "poetry update requests"},
		"pipenv":         {"Pipfile.lock", "{}", "pipenv update requests"},
		"pyproject":      {"pyproject.toml", "", "pyproject.toml"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			p := write(t, tc.file, tc.body)
			adv := AdviceFor(p, "requests", "2.31.0", "2.32.0")
			if adv.Command != "" {
				t.Fatalf("offered %q for something a pin edit cannot do", adv.Command)
			}
			if !strings.Contains(adv.Manual, tc.why) {
				t.Errorf("manual reason %q does not mention %q", adv.Manual, tc.why)
			}
			if err := adv.Apply(); err == nil {
				t.Error("Apply succeeded on a manual fix")
			}
			if got, _ := os.ReadFile(p); string(got) != tc.body {
				t.Errorf("the file changed: %q", got)
			}
		})
	}
}

// The file changed between advice and apply: refuse rather than write over it.
func TestApplyRefusesAFileThatChanged(t *testing.T) {
	p := write(t, "requirements.txt", "requests==2.31.0\n")
	adv := AdviceFor(p, "requests", "2.31.0", "2.32.0")
	if err := os.WriteFile(p, []byte("requests==2.31.0\nflask==3.0.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := adv.Apply(); err == nil {
		t.Error("applied an edit to a file that changed since it was read")
	}
}
