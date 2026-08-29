package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

// runIntelRegister creates an operator and prints their enrolment link.
//
// Registration and second-factor setup are one act. An account with no
// authenticator cannot sign in at all, so creating one without an invitation
// leaves a person who exists and cannot get in — and the thing reached for in
// that gap is the shared operator token, which is what this replaces.
func runIntelRegister(args []string) int {
	cmdName = "nox intel add-operator"
	fs := flag.NewFlagSet("intel register", flag.ContinueOnError)
	endpoint := fs.String("endpoint", os.Getenv("NOX_INTEL_ENDPOINT"),
		"intelligence service base URL (or NOX_INTEL_ENDPOINT)")
	email := fs.String("email", "", "address of the operator to register")
	org := fs.String("org", "", "organisation to register them into")
	role := fs.String("role", "member", "member or admin")
	verified := fs.Bool("verified", true,
		"mark the address proven (you are vouching for it by registering them)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	// A session is the ordinary path. The operator token remains for the first
	// admin, who by definition cannot sign in as one yet.
	s, signedIn := loadSession()
	base := strings.TrimRight(*endpoint, "/")
	if base == "" && signedIn {
		base = s.Endpoint
	}
	token := os.Getenv("NOX_INTEL_TOKEN")

	if base == "" || *email == "" || *org == "" {
		fmt.Fprintf(os.Stderr, "Usage: nox intel register --email them@example.com --org ORG [--role admin]\n\n")
		fmt.Fprintf(os.Stderr, "Sign in first with `nox intel login`; the endpoint is then remembered.\n")
		fmt.Fprintf(os.Stderr, "--org is required: a role is held in an organisation, so registering\n")
		fmt.Fprintf(os.Stderr, "without one would leave the account with no owner.\n")
		return 2
	}
	if *role != "member" && *role != "admin" {
		fmt.Fprintf(os.Stderr, "nox intel register: --role must be member or admin\n")
		return 2
	}
	if !signedIn && token == "" {
		fmt.Fprintf(os.Stderr, "nox intel register: not signed in, and NOX_INTEL_TOKEN is not set.\n")
		fmt.Fprintf(os.Stderr, "Run `nox intel login`. The operator token is only for registering\n")
		fmt.Fprintf(os.Stderr, "the very first admin, when there is no admin to sign in as.\n")
		return 2
	}
	if signedIn && sessionExpired(s) {
		fmt.Fprintf(os.Stderr, "nox intel register: your session has expired. Run `nox intel login`.\n")
		return 2
	}

	auth := token
	if signedIn {
		auth = s.Token
	}
	var out struct {
		Email     string `json:"email"`
		URL       string `json:"enrollment_url"`
		ExpiresAt string `json:"enrollment_expires_at"`
		EnrolErr  string `json:"enrollment_error"`
		Error     string `json:"error"`
	}
	if code := postJSON(base+"/v1/admin/subjects", auth, map[string]any{
		"email": *email, "org_id": *org, "role": *role, "verified": *verified,
	}, &out); code != 0 {
		return code
	}

	fmt.Printf("Registered %s in %s as %s.\n", *email, *org, *role)
	if out.EnrolErr != "" {
		fmt.Fprintf(os.Stderr, "\nwarning: %s\n", out.EnrolErr)
		fmt.Fprintf(os.Stderr, "They exist but cannot sign in yet. Issue a link with:\n")
		fmt.Fprintf(os.Stderr, "  nox intel invite --email %s\n", *email)
		return 1
	}
	if out.URL == "" {
		fmt.Fprintf(os.Stderr, "\nwarning: no enrolment link was returned; they cannot sign in yet.\n")
		return 1
	}
	fmt.Printf("\nSend them this link. It works once and expires%s:\n\n  %s\n\n",
		expiryPhrase(out.ExpiresAt), out.URL)
	fmt.Printf("Or they can run:\n\n  nox intel enroll --endpoint %s --code <code from the link>\n", base)
	return 0
}

// runIntelInvite re-issues an enrolment link for someone who already exists.
func runIntelInvite(args []string) int {
	cmdName = "nox intel invite"
	fs := flag.NewFlagSet("intel invite", flag.ContinueOnError)
	endpoint := fs.String("endpoint", os.Getenv("NOX_INTEL_ENDPOINT"),
		"intelligence service base URL (or NOX_INTEL_ENDPOINT)")
	email := fs.String("email", "", "address of the operator to re-invite")
	org := fs.String("org", "",
		"organisation they belong to (only needed if you administer more than one)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	s, signedIn := loadSession()
	base := strings.TrimRight(*endpoint, "/")
	if base == "" && signedIn {
		base = s.Endpoint
	}
	token := os.Getenv("NOX_INTEL_TOKEN")
	if base == "" || *email == "" {
		fmt.Fprintf(os.Stderr, "Usage: nox intel invite --email them@example.com\n\n")
		fmt.Fprintf(os.Stderr, "Issues a fresh enrolment link. Any previous link for that\n")
		fmt.Fprintf(os.Stderr, "address stops working, so two live invitations never coexist.\n")
		return 2
	}
	auth := token
	if signedIn {
		auth = s.Token
	}
	if auth == "" {
		fmt.Fprintf(os.Stderr, "nox intel invite: not signed in, and NOX_INTEL_TOKEN is not set.\n")
		return 2
	}
	var out struct {
		URL       string `json:"enrollment_url"`
		ExpiresAt string `json:"enrollment_expires_at"`
	}
	if code := postJSON(base+"/v1/admin/enrollments", auth,
		map[string]string{"email": *email, "org_id": *org}, &out); code != 0 {
		return code
	}
	fmt.Printf("New enrolment link for %s. It works once and expires%s:\n\n  %s\n",
		*email, expiryPhrase(out.ExpiresAt), out.URL)
	fmt.Printf("\nAny earlier link for this address is now invalid.\n")
	return 0
}

func expiryPhrase(at string) string {
	if at == "" {
		return ""
	}
	return " at " + at
}
