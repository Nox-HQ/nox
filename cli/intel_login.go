package main

import (
	"flag"
	"fmt"
	"net/http"
	"net/url"
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
	noBrowser := fs.Bool("no-browser", false,
		"print the URL and code instead of opening a browser")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *endpoint == "" {
		fmt.Fprintf(os.Stderr, "Usage: nox intel login --endpoint URL\n\n")
		fmt.Fprintf(os.Stderr, "Opens your browser to approve this terminal. Your authenticator\n")
		fmt.Fprintf(os.Stderr, "code is never typed here — it stays in the browser, where it\n")
		fmt.Fprintf(os.Stderr, "cannot end up in scrollback or a captured log.\n")
		return 2
	}
	base := strings.TrimRight(*endpoint, "/")
	if _, err := url.Parse(base); err != nil {
		fmt.Fprintf(os.Stderr, "nox intel login: bad endpoint: %v\n", err)
		return 2
	}

	// Browser sign-in cannot work where nobody is watching. Failing here with
	// the fix beats hanging for five minutes in a pipeline.
	if isCI() && !*noBrowser {
		fmt.Fprintf(os.Stderr, "nox intel login: this looks like CI, where nobody can approve a browser prompt.\n")
		fmt.Fprintf(os.Stderr, "Use a scoped token in NOX_INTEL_TOKEN instead, or pass --no-browser\n")
		fmt.Fprintf(os.Stderr, "if a person really is watching this terminal.\n")
		return 2
	}

	return runIntelLoginDevice(base, !*noBrowser)
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
	req, err := http.NewRequest(http.MethodPost, s.Endpoint+"/v1/auth/logout", http.NoBody)
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
	req, err := http.NewRequest(http.MethodGet, s.Endpoint+"/v1/auth/session", http.NoBody)
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
