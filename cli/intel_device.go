package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// Device-flow sign-in: OAuth 2.0 Device Authorization Grant, RFC 8628.
//
// The previous login asked for a TOTP code at the prompt, which put a live
// authentication code into scrollback, tmux history and captured CI output —
// the same objection that keeps the provisioning QR out of the terminal. Here
// the terminal only ever holds a user code, which does nothing until a person
// approves it in an already-authenticated browser.

// deviceFlowCap bounds polling regardless of what the server says.
//
// RFC 8628 §5.4: a user code is short enough for a human to retype, so it is
// short enough to guess at. The server sets its own expiry; this is a second
// ceiling the client controls, so a server that advertises an hour cannot make
// this terminal sit on a guessable code for an hour.
const deviceFlowCap = 5 * time.Minute

// deviceMinInterval floors the poll gap. A server asking to be polled every
// 100ms is either broken or hostile; either way this client will not do it.
const deviceMinInterval = 1 * time.Second

// deviceSlowDownBump is the increase RFC 8628 §3.5 requires on slow_down.
const deviceSlowDownBump = 5 * time.Second

type deviceAuth struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// runIntelLoginDevice signs in through the device flow.
func runIntelLoginDevice(base string, openBrowser bool) int {
	auth, code := requestDeviceAuthorization(base)
	if code != 0 {
		return code
	}

	// The verification URL comes from the server, and it is the one URL this
	// command will open. Check it points where we asked before printing it as
	// trustworthy or handing it to a browser — RFC 8628 §5.4 names remote
	// phishing as the risk, and an intermediary that rewrites this field is
	// exactly how that happens.
	target := auth.VerificationURIComplete
	if target == "" {
		target = auth.VerificationURI
	}
	if err := checkVerificationURL(base, auth.VerificationURI, target); err != nil {
		fmt.Fprintf(os.Stderr, "nox login: %v\n", err)
		fmt.Fprintf(os.Stderr, "Refusing to open it. The service returned a verification URL\n")
		fmt.Fprintf(os.Stderr, "that does not belong to %s.\n", base)
		return 1
	}

	// Always print the bare URI and the code, even though a complete URL
	// exists. RFC 8628 §3.3.1 requires it: the operator confirms the code in
	// the browser, and that confirmation is what stops someone being talked
	// into approving a sign-in they did not start.
	fmt.Printf("\nTo sign in, open:\n\n  %s\n\nand enter the code:\n\n  %s\n\n",
		auth.VerificationURI, auth.UserCode)

	if openBrowser {
		if err := openInBrowser(target); err != nil {
			fmt.Fprintf(os.Stderr, "Could not open a browser (%v). Use the URL above.\n", err)
		}
	} else {
		fmt.Printf("Not opening a browser. Approve it from any device.\n")
	}

	fmt.Printf("Waiting for approval (up to %d minutes)…\n", int(deviceFlowCap.Minutes()))
	return pollForDeviceSession(base, auth)
}

func requestDeviceAuthorization(base string) (auth deviceAuth, exitCode int) {
	body, status, err := postJSONRaw(base+"/v1/auth/device", "", map[string]string{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "nox login: %v\n", err)
		return auth, 1
	}
	if status == http.StatusNotFound {
		fmt.Fprintf(os.Stderr, "nox login: this service does not offer device sign-in.\n")
		fmt.Fprintf(os.Stderr, "It may be running a version before that existed.\n")
		return auth, 1
	}
	if status >= 300 {
		fmt.Fprintf(os.Stderr, "nox login: could not start sign-in (HTTP %d)\n", status)
		return auth, 1
	}
	if err := json.Unmarshal(body, &auth); err != nil || auth.DeviceCode == "" || auth.UserCode == "" {
		fmt.Fprintf(os.Stderr, "nox login: the service returned an unusable device authorization\n")
		return auth, 1
	}
	return auth, 0
}

// pollForDeviceSession waits for approval and stores the session.
func pollForDeviceSession(base string, auth deviceAuth) int {
	interval := time.Duration(auth.Interval) * time.Second
	if interval < deviceMinInterval {
		interval = deviceMinInterval
	}
	// Whichever ceiling is lower wins: the server's expiry, or ours.
	deadline := time.Now().Add(deviceFlowCap)
	if auth.ExpiresIn > 0 {
		if serverDeadline := time.Now().Add(time.Duration(auth.ExpiresIn) * time.Second); serverDeadline.Before(deadline) {
			deadline = serverDeadline
		}
	}

	for {
		if time.Now().After(deadline) {
			fmt.Fprintf(os.Stderr, "\nnox login: timed out waiting for approval.\n")
			fmt.Fprintf(os.Stderr, "Run `nox login` again to start over.\n")
			return 1
		}
		raw, status, err := postJSONRaw(base+"/v1/auth/device/token", "",
			map[string]string{"device_code": auth.DeviceCode})
		if err != nil {
			// A transient network failure must not end the flow: the operator
			// may already be approving it in the browser.
			time.Sleep(interval)
			continue
		}
		if status < 300 {
			return storeDeviceSession(base, raw)
		}

		switch deviceErrorOf(raw) {
		case "authorization_pending":
			// Expected until somebody clicks approve.
		case "slow_down":
			interval += deviceSlowDownBump
		case "access_denied":
			fmt.Fprintf(os.Stderr, "\nnox login: the sign-in was denied in the browser.\n")
			return 1
		case "expired_token":
			fmt.Fprintf(os.Stderr, "\nnox login: the code expired before it was approved.\n")
			fmt.Fprintf(os.Stderr, "Run `nox login` again.\n")
			return 1
		default:
			fmt.Fprintf(os.Stderr, "\nnox login: sign-in failed (HTTP %d)\n", status)
			return 1
		}
		time.Sleep(interval)
	}
}

func storeDeviceSession(base string, raw []byte) int {
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresAt   string `json:"expires_at"`
		Email       string `json:"email"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || out.AccessToken == "" {
		fmt.Fprintf(os.Stderr, "nox login: approved, but the service returned no session\n")
		return 1
	}
	s := session{Endpoint: base, Email: out.Email, Token: out.AccessToken, ExpiresAt: out.ExpiresAt}
	if err := saveSession(s); err != nil {
		fmt.Fprintf(os.Stderr, "nox login: signed in, but the session could not be stored: %v\n", err)
		return 1
	}
	fmt.Printf("\nSigned in to %s as %s.\n", base, out.Email)
	if out.ExpiresAt != "" {
		fmt.Printf("The session expires at %s.\n", out.ExpiresAt)
	}
	return 0
}

// checkVerificationURL refuses a verification URL that is not https on the same
// host the operator asked for.
//
// This is the only URL the command opens that it did not build itself. An
// intermediary — or a compromised endpoint — that returns someone else's URL
// here turns `nox login` into a phishing delivery mechanism, and the operator
// has no reason to distrust a link their own tool just opened.
func checkVerificationURL(base, verification, complete string) error {
	want, err := url.Parse(base)
	if err != nil {
		return fmt.Errorf("bad endpoint %q: %w", base, err)
	}
	for _, raw := range []string{verification, complete} {
		if raw == "" {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil {
			return fmt.Errorf("unparseable verification URL %q", raw)
		}
		if u.Scheme != want.Scheme {
			return fmt.Errorf("verification URL scheme is %q, expected %q", u.Scheme, want.Scheme)
		}
		if !strings.EqualFold(u.Host, want.Host) {
			return fmt.Errorf("verification URL host is %q, expected %q", u.Host, want.Host)
		}
		// Credentials in a URL are a classic way to make one host look like
		// another in a browser's address bar.
		if u.User != nil {
			return errors.New("verification URL carries embedded credentials")
		}
	}
	return nil
}

// openInBrowser opens a URL with the platform's opener.
func openInBrowser(target string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", target)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", target)
	default:
		cmd = exec.Command("xdg-open", target)
	}
	return cmd.Start()
}

// deviceErrorOf reads the OAuth error code out of a response body.
func deviceErrorOf(raw []byte) string {
	var e struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(raw, &e)
	return e.Error
}

// postJSONRaw is postJSON without the error printing, for callers that branch
// on the status themselves.
func postJSONRaw(endpoint, token string, body any) (raw []byte, status int, err error) {
	buf, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(buf))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ = io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return raw, resp.StatusCode, nil
}

// isCI reports whether this looks like an automated environment.
//
// Browser-based sign-in cannot work where nobody is watching, and hanging for
// five minutes in a pipeline is worse than failing immediately with the fix.
func isCI() bool {
	for _, k := range []string{"CI", "GITHUB_ACTIONS", "GITLAB_CI", "BUILDKITE", "CIRCLECI", "JENKINS_URL"} {
		if os.Getenv(k) != "" {
			return true
		}
	}
	return false
}
