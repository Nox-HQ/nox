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
	fs := flag.NewFlagSet("intel enroll", flag.ContinueOnError)
	endpoint := fs.String("endpoint", os.Getenv("NOX_INTEL_ENDPOINT"),
		"intelligence service base URL (or NOX_INTEL_ENDPOINT)")
	email := fs.String("email", "", "operator address to enrol")
	yes := fs.Bool("no-confirm", false,
		"print the URI and exit without confirming (the new factor stays inactive)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *endpoint == "" || *email == "" {
		fmt.Fprintf(os.Stderr, "Usage: nox intel enroll --endpoint URL --email you@example.com\n\n")
		fmt.Fprintf(os.Stderr, "The operator token is read from NOX_INTEL_TOKEN. It is required:\n")
		fmt.Fprintf(os.Stderr, "enrolment is the account-recovery path, so it cannot be anonymous.\n")
		return 2
	}
	token := os.Getenv("NOX_INTEL_TOKEN")
	if token == "" {
		fmt.Fprintf(os.Stderr, "nox intel enroll: NOX_INTEL_TOKEN is not set.\n")
		fmt.Fprintf(os.Stderr, "Enrolment replaces a second factor, so it requires the operator token.\n")
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
	if code := postJSON(base+"/v1/auth/enroll", token,
		map[string]string{"email": *email}, &begin); code != 0 {
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

func postJSON(endpoint, token string, body, out any) int {
	buf, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(buf))
	if err != nil {
		fmt.Fprintf(os.Stderr, "nox intel enroll: %v\n", err)
		return 1
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "nox intel enroll: %v\n", err)
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
		fmt.Fprintf(os.Stderr, "nox intel enroll: %s (HTTP %d)\n", msg, resp.StatusCode)
		return 1
	}
	return 0
}
