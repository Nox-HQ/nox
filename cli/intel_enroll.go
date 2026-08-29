package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// runIntelEnroll registers a second factor for an intelligence-service operator.
//
// Deliberately no QR in the terminal. A block-drawing QR depends on the font,
// the colour scheme and the window size, and the failure mode is a symbol that
// looks right and will not scan — which is worse than no symbol, because the
// operator only discovers it when they next need to sign in. The terminal is
// good at exact text, so it prints exact text: the otpauth URI, and the secret
// for hand entry. The console at /  renders a scannable code for anyone who
// wants one.
//
// Two steps, and the second is the point. The candidate secret is not active
// until a code from the new app confirms it, so a mistyped code or an app that
// was never installed leaves the existing authenticator working.
func runIntelEnroll(args []string) int {
	cmdName = "nox intel enroll"
	fs := flag.NewFlagSet("intel enroll", flag.ContinueOnError)
	endpoint := fs.String("endpoint", os.Getenv("NOX_INTEL_ENDPOINT"),
		"intelligence service base URL (or NOX_INTEL_ENDPOINT)")
	email := fs.String("email", "", "operator address to enrol")
	yes := fs.Bool("no-confirm", false,
		"print the URI and exit without confirming (the new factor stays inactive)")
	invite := fs.String("code", "",
		"single-use enrolment code from your invitation (no operator token needed)")
	save := fs.String("save-recovery-codes", "",
		"write the recovery codes to this file (created 0600) as well as printing them")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	// An invitation names its own subject, so --email is neither needed nor
	// honoured with one: the address comes from the code server-side.
	if *endpoint == "" || (*email == "" && *invite == "") {
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  nox intel enroll --endpoint URL --code CODE          # from an invitation\n")
		fmt.Fprintf(os.Stderr, "  nox intel enroll --endpoint URL --email you@example.com   # break-glass\n\n")
		fmt.Fprintf(os.Stderr, "An invitation is the ordinary path and needs no operator token.\n")
		fmt.Fprintf(os.Stderr, "The token (NOX_INTEL_TOKEN) is for the case an invitation cannot cover:\n")
		fmt.Fprintf(os.Stderr, "an operator who has lost their phone and holds no valid link.\n")
		return 2
	}
	// The operator token is required only without an invitation. Demanding it
	// in both cases is what trains people to keep it somewhere convenient,
	// which is the habit this flow exists to remove.
	token := os.Getenv("NOX_INTEL_TOKEN")
	if token == "" && *invite == "" {
		fmt.Fprintf(os.Stderr, "nox intel enroll: no --code, and NOX_INTEL_TOKEN is not set.\n")
		fmt.Fprintf(os.Stderr, "Use the enrolment code from your invitation, or set the operator\n")
		fmt.Fprintf(os.Stderr, "token if you are recovering an account with no valid invitation.\n")
		return 2
	}
	base := strings.TrimRight(*endpoint, "/")
	if _, err := url.Parse(base); err != nil {
		fmt.Fprintf(os.Stderr, "nox intel enroll: bad endpoint: %v\n", err)
		return 2
	}

	var begin struct {
		ProvisioningURI string `json:"provisioning_uri"`
		EnrollmentToken string `json:"enrollment_token"`
		ExpiresIn       int    `json:"expires_in"`
		Error           string `json:"error"`
	}
	beginBody := map[string]string{"email": *email}
	if *invite != "" {
		beginBody = map[string]string{"enrollment_code": *invite}
	}
	if code := postJSON(base+"/v1/auth/enroll", token, beginBody, &begin); code != 0 {
		return code
	}
	if begin.ProvisioningURI == "" {
		fmt.Fprintf(os.Stderr, "nox intel enroll: the service returned no provisioning URI\n")
		return 1
	}

	secret := ""
	if u, err := url.Parse(begin.ProvisioningURI); err == nil {
		secret = u.Query().Get("secret")
	}
	fmt.Printf("Add this to an authenticator app:\n\n")
	fmt.Printf("  %s\n\n", begin.ProvisioningURI)
	if secret != "" {
		fmt.Printf("Or enter the secret by hand:\n\n  %s\n\n", spaced(secret))
	}
	fmt.Printf("For a scannable QR code, use the console at %s\n\n", base+"/")
	fmt.Printf("Your existing authenticator keeps working until you confirm below.\n")

	if *yes {
		fmt.Printf("\nNot confirmed. The new factor is inactive and expires in %s.\n",
			(time.Duration(begin.ExpiresIn) * time.Second).Round(time.Minute))
		return 0
	}

	fmt.Printf("\nCode from the new app: ")
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && strings.TrimSpace(line) == "" {
		fmt.Fprintf(os.Stderr, "\nnox intel enroll: no code entered; the new factor was NOT activated.\n")
		return 1
	}
	var done struct {
		Enrolled           bool     `json:"enrolled"`
		Email              string   `json:"email"`
		RecoveryCodes      []string `json:"recovery_codes"`
		RecoveryCodesError string   `json:"recovery_codes_error"`
		Error              string   `json:"error"`
	}
	if code := postJSON(base+"/v1/auth/enroll/confirm", token, map[string]string{
		"email": *email, "enrollment_token": begin.EnrollmentToken,
		"code": strings.TrimSpace(line),
	}, &done); code != 0 {
		fmt.Fprintf(os.Stderr, "The new factor was NOT activated; your existing one still works.\n")
		return code
	}
	fmt.Printf("Enrolled.\n")

	// Recovery codes are printed here because this is the one moment they
	// exist. They are shown once; a run that scrolls them past the operator
	// has failed at the thing it was for.
	if len(done.RecoveryCodes) > 0 {
		fmt.Printf("\nRecovery codes — save these now. Each works once, in place of a\n")
		fmt.Printf("code from your app, and they are shown only here.\n\n")
		for _, c := range done.RecoveryCodes {
			fmt.Printf("  %s\n", c)
		}
		fmt.Printf("\nWithout them, a lost phone means the operator token is the only\n")
		fmt.Printf("way back in — which is how this service's own lockout had to be fixed.\n")
		// Writing them out is offered because "save these now" is advice people
		// postpone, and there is no second showing. 0600 and O_EXCL: this file
		// holds every way back into the account, and silently overwriting an
		// existing set of codes would destroy the ones already in use.
		if *save != "" {
			f, err := os.OpenFile(*save, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
			if err != nil {
				fmt.Fprintf(os.Stderr, "\nwarning: could not write %s: %v\n", *save, err)
				fmt.Fprintf(os.Stderr, "The codes above are still valid — copy them now, they are not shown again.\n")
			} else {
				_, werr := fmt.Fprintf(f, "NOX Intelligence recovery codes for %s\nEach works once, in place of a code from your authenticator.\n\n%s\n",
					done.Email, strings.Join(done.RecoveryCodes, "\n"))
				cerr := f.Close()
				if werr != nil || cerr != nil {
					fmt.Fprintf(os.Stderr, "\nwarning: %s may be incomplete; copy the codes above instead\n", *save)
				} else {
					fmt.Printf("\nAlso written to %s (mode 0600).\n", *save)
				}
			}
		}
	} else if done.RecoveryCodesError != "" {
		fmt.Fprintf(os.Stderr, "\nwarning: %s\n", done.RecoveryCodesError)
	}
	fmt.Printf("\nSign in at %s with a code from the app, or one of the codes above.\n", base+"/")
	return 0
}

// spaced groups a base32 secret in fours, which is how every authenticator app
// displays it for manual entry and the only realistic way to type 32 characters
// without an error.
func spaced(s string) string {
	var b strings.Builder
	for i, r := range s {
		if i > 0 && i%4 == 0 {
			b.WriteByte(' ')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// cmdName labels errors from postJSON. It is shared by enroll, add-operator
// and invite, and hardcoding one of them meant `nox intel invite` failed with
// "nox intel enroll: unauthorized" — which sends the reader to the wrong
// command's docs.
var cmdName = "nox intel"

func postJSON(endpoint, token string, body, out any) int {
	buf, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(buf))
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", cmdName, err)
		return 1
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", cmdName, err)
		return 1
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_ = json.Unmarshal(raw, out)
	if resp.StatusCode >= 300 {
		msg := ""
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(raw, &e) == nil {
			msg = e.Error
		}
		if msg == "" {
			msg = strings.TrimSpace(string(raw))
		}
		fmt.Fprintf(os.Stderr, "%s: %s (HTTP %d)\n", cmdName, msg, resp.StatusCode)
		return 1
	}
	return 0
}
