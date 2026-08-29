package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The verification URL is the only URL `nox login` opens that it did not build
// itself. RFC 8628 §5.4 names remote phishing as the risk: a compromised or
// intermediated endpoint that returns somebody else's URL turns the login
// command into a delivery mechanism, and the operator has no reason to distrust
// a link their own tool just opened.
func TestVerificationURLMustBelongToTheEndpoint(t *testing.T) {
	const base = "https://intel.klarlabs.de"

	ok := []struct{ name, verification, complete string }{
		{"same host", base + "/device", base + "/device?user_code=ABCD-EFGH"},
		{"bare only", base + "/device", ""},
		{"case-insensitive host", "https://INTEL.klarlabs.de/device", ""},
	}
	for _, c := range ok {
		if err := checkVerificationURL(base, c.verification, c.complete); err != nil {
			t.Errorf("%s: rejected a legitimate URL: %v", c.name, err)
		}
	}

	bad := []struct{ name, verification, complete string }{
		{"different host", "https://evil.example/device", ""},
		{"lookalike subdomain", "https://intel.klarlabs.de.evil.example/device", ""},
		{"downgraded to http", "http://intel.klarlabs.de/device", ""},
		// Host is intact here on purpose: with a mismatched host the host check
		// fires first and the credential check never decides, which is exactly
		// how this case was vacuous when first written.
		{"credentials on the right host", "https://user:pass@intel.klarlabs.de/device", ""},
		{"credentials making another host look right", "https://intel.klarlabs.de@evil.example/device", ""},
		{"complete URL diverges", base + "/device", "https://evil.example/device?user_code=X"},
		{"unparseable", "://nonsense", ""},
	}
	for _, c := range bad {
		if err := checkVerificationURL(base, c.verification, c.complete); err == nil {
			t.Errorf("%s: accepted %q / %q — this is the phishing case", c.name, c.verification, c.complete)
		}
	}
}

// The client's own ceiling must bound polling regardless of what the server
// advertises. A server that claims an hour must not be able to make a terminal
// sit on a guessable code for an hour.
func TestClientCapsPollingIndependentlyOfTheServer(t *testing.T) {
	if deviceFlowCap > 10*time.Minute {
		t.Errorf("deviceFlowCap is %v; a user code is short enough to guess at, so the "+
			"client's own ceiling must stay small", deviceFlowCap)
	}
	if deviceMinInterval < time.Second {
		t.Error("the poll interval floor is below a second; a server asking to be polled " +
			"faster than that is broken or hostile")
	}
	if deviceSlowDownBump != 5*time.Second {
		t.Errorf("slow_down bump is %v, RFC 8628 §3.5 requires 5s", deviceSlowDownBump)
	}
}

// The OAuth error codes drive control flow, so they must be read from the body
// rather than inferred from the status.
func TestDeviceErrorCodesAreParsed(t *testing.T) {
	for body, want := range map[string]string{
		`{"error":"authorization_pending"}`: "authorization_pending",
		`{"error":"slow_down"}`:             "slow_down",
		`{"error":"access_denied"}`:         "access_denied",
		`{"error":"expired_token"}`:         "expired_token",
		`{}`:                                "",
		`not json`:                          "",
	} {
		if got := deviceErrorOf([]byte(body)); got != want {
			t.Errorf("deviceErrorOf(%s) = %q, want %q", body, got, want)
		}
	}
}

// CI has nobody to approve a browser prompt. Hanging for five minutes in a
// pipeline is worse than failing immediately with the fix.
func TestCIIsDetected(t *testing.T) {
	for _, k := range []string{"CI", "GITHUB_ACTIONS", "GITLAB_CI", "BUILDKITE", "CIRCLECI", "JENKINS_URL"} {
		t.Setenv(k, "")
	}
	if isCI() {
		t.Fatal("isCI() true with every marker cleared")
	}
	t.Setenv("GITHUB_ACTIONS", "true")
	if !isCI() {
		t.Error("GITHUB_ACTIONS set but isCI() is false")
	}
}

// The login command must never ask for an authenticator code. That is the whole
// reason the device flow replaced the previous prompt: a code typed at a prompt
// lands in scrollback, tmux history and captured CI output.
func TestLoginNeverPromptsForACode(t *testing.T) {
	src, err := readSource("cli/intel_login.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"ReadString('\\n')", "bufio.NewReader(os.Stdin)", "authenticator code"} {
		if strings.Contains(src, bad) {
			t.Errorf("intel_login.go still contains %q — the code must stay in the browser", bad)
		}
	}
}

// readSource reads a file relative to the module root, so a test can assert
// about the shape of the command rather than only its behaviour.
func readSource(rel string) (string, error) {
	b, err := os.ReadFile(filepath.Join("..", rel))
	return string(b), err
}

// `register` must not create anything. Creating a tenant is where terms,
// billing and address verification live, and no comparable tool lets a CLI do
// it — GitHub, Vercel and Cloudflare all create the org on the web.
//
// The command exists as a signpost because the alternative is someone typing it,
// getting "unknown subcommand", and guessing.
func TestRegisterOnlyPointsAtTheWeb(t *testing.T) {
	src, err := readSource("cli/intel_signup.go")
	if err != nil {
		t.Fatal(err)
	}
	// It must not call the admin API to create anything.
	for _, bad := range []string{"/v1/admin/orgs", "/v1/admin/subjects", "postJSON("} {
		if strings.Contains(src, bad) {
			t.Errorf("intel register calls %q; creating a tenant from a CLI is the thing "+
				"this command exists to avoid", bad)
		}
	}
	if !strings.Contains(src, "/signup") {
		t.Error("intel register does not point at the sign-up page")
	}
}

// Adding an operator is a different act from creating a tenant, and conflating
// them under one verb is how somebody ends up creating a tenant by accident.
func TestOperatorCreationHasItsOwnVerb(t *testing.T) {
	src, err := readSource("cli/intel_cmd.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(src, `case "add-operator":`) {
		t.Error("no distinct verb for adding an operator")
	}
	if !strings.Contains(src, "runIntelSignup") {
		t.Error("`register` is not wired to the web sign-up")
	}
}
