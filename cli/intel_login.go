package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// runIntelLogin signs an operator in and stores the session.
//
// This exists so that operating the intelligence service does not mean pasting
// a shared token into curl. A session is per-person, carries the second factor,
// and can be revoked for one operator without disturbing anyone else.
func runIntelLogin(args []string) int {
	fs := flag.NewFlagSet("intel login", flag.ContinueOnError)
	endpoint := fs.String("endpoint", os.Getenv("NOX_INTEL_ENDPOINT"),
		"intelligence service base URL (or NOX_INTEL_ENDPOINT)")
	email := fs.String("email", "", "your operator address")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *endpoint == "" || *email == "" {
		fmt.Fprintf(os.Stderr, "Usage: nox intel login --endpoint URL --email you@example.com\n\n")
		fmt.Fprintf(os.Stderr, "You will be asked for a code from your authenticator.\n")
		fmt.Fprintf(os.Stderr, "A recovery code works here too, and is spent when you use it.\n")
		return 2
	}
	base := strings.TrimRight(*endpoint, "/")

	fmt.Printf("Code from your authenticator (or a recovery code): ")
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && strings.TrimSpace(line) == "" {
		fmt.Fprintf(os.Stderr, "\nnox intel login: no code entered.\n")
		return 2
	}
	code := strings.TrimSpace(line)

	// The session cookie is what the browser uses; the CLI asks for the same
	// credential as a bearer token so it can be stored without a cookie jar.
	buf, _ := json.Marshal(map[string]string{"email": *email, "code": code})
	req, err := http.NewRequest(http.MethodPost, base+"/v1/auth/login", bytes.NewReader(buf))
	if err != nil {
		fmt.Fprintf(os.Stderr, "nox intel login: %v\n", err)
		return 1
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "nox intel login: %v\n", err)
		return 1
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode >= 300 {
		// The service does not say whether the address exists or the code was
		// wrong, and neither does this: repeating a deliberately vague answer
		// more precisely would undo the reason it is vague.
		fmt.Fprintf(os.Stderr, "nox intel login: invalid credentials (HTTP %d)\n", resp.StatusCode)
		fmt.Fprintf(os.Stderr, "If the code looked right, check the clock on your phone —\n")
		fmt.Fprintf(os.Stderr, "TOTP allows only a small window of drift.\n")
		return 1
	}

	tok := sessionTokenFrom(resp, raw)
	if tok == "" {
		fmt.Fprintf(os.Stderr, "nox intel login: signed in, but the service returned no session token\n")
		return 1
	}
	s := session{Endpoint: base, Email: *email, Token: tok}
	var body struct {
		ExpiresAt string `json:"expires_at"`
	}
	if json.Unmarshal(raw, &body) == nil {
		s.ExpiresAt = body.ExpiresAt
	}
	if err := saveSession(s); err != nil {
		fmt.Fprintf(os.Stderr, "nox intel login: signed in, but the session could not be stored: %v\n", err)
		return 1
	}
	fmt.Printf("Signed in to %s as %s.\n", base, *email)
	if s.ExpiresAt != "" {
		fmt.Printf("The session expires at %s.\n", s.ExpiresAt)
	}
	return 0
}

// sessionTokenFrom finds the session credential in a login response.
//
// Preferring an explicit field and falling back to the cookie, because the
// console is the primary client and is cookie-based; a CLI that only understood
// one of the two would break the moment the other changed.
func sessionTokenFrom(resp *http.Response, raw []byte) string {
	var body struct {
		Token   string `json:"token"`
		Session string `json:"session"`
	}
	if json.Unmarshal(raw, &body) == nil {
		if body.Token != "" {
			return body.Token
		}
		if body.Session != "" {
			return body.Session
		}
	}
	for _, ck := range resp.Cookies() {
		if strings.Contains(ck.Name, "nox_session") {
			return ck.Value
		}
	}
	return ""
}

// runIntelLogout revokes the session server-side, then forgets it.
//
// Server first: a token dropped locally but still valid on the server is a live
// credential the operator believes they have destroyed. If the revocation call
// fails the local copy is still removed, and the failure is reported rather
// than swallowed.
func runIntelLogout(args []string) int {
	fs := flag.NewFlagSet("intel logout", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	s, ok := loadSession()
	if !ok {
		fmt.Println("Not signed in.")
		return 0
	}
	req, err := http.NewRequest(http.MethodPost, s.Endpoint+"/v1/auth/logout", nil)
	if err == nil {
		req.Header.Set("Authorization", "Bearer "+s.Token)
		if resp, derr := (&http.Client{Timeout: 30 * time.Second}).Do(req); derr == nil {
			_ = resp.Body.Close()
			if resp.StatusCode >= 300 {
				fmt.Fprintf(os.Stderr,
					"warning: the service did not confirm revocation (HTTP %d); the local copy is gone but the session may still be valid\n",
					resp.StatusCode)
			}
		} else {
			fmt.Fprintf(os.Stderr,
				"warning: could not reach the service to revoke the session: %v\n", derr)
		}
	}
	clearSession()
	fmt.Printf("Signed out of %s.\n", s.Endpoint)
	return 0
}

// runIntelWhoami reports the stored session without making a request unless it
// has to, so "am I signed in?" is answerable offline.
func runIntelWhoami(args []string) int {
	fs := flag.NewFlagSet("intel whoami", flag.ContinueOnError)
	check := fs.Bool("check", false, "ask the service whether the session is still valid")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	s, ok := loadSession()
	if !ok {
		fmt.Println("Not signed in. Run: nox intel login --endpoint URL --email you@example.com")
		return 1
	}
	fmt.Printf("%s at %s\n", s.Email, s.Endpoint)
	if sessionExpired(s) {
		fmt.Println("This session has expired. Sign in again.")
		return 1
	}
	if s.ExpiresAt != "" {
		fmt.Printf("Expires at %s.\n", s.ExpiresAt)
	}
	if !*check {
		return 0
	}
	req, err := http.NewRequest(http.MethodGet, s.Endpoint+"/v1/auth/session", nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "nox intel whoami: %v\n", err)
		return 1
	}
	req.Header.Set("Authorization", "Bearer "+s.Token)
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "nox intel whoami: %v\n", err)
		return 1
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		fmt.Println("The service rejected this session. Sign in again.")
		return 1
	}
	fmt.Println("The service accepts this session.")
	return 0
}
