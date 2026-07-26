package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nox-hq/nox/core/findings"
)

// Secret validity checking: does a detected credential still work?
//
// A detected secret and a LIVE secret are different findings. "This looks like
// a GitHub token" is a backlog item; "this is a working token for account X" is
// an incident, because the credential is already public and the only fix is
// rotation. Only the issuer can tell those apart — and, usefully, the check
// needs no privilege beyond the leaked credential itself.
//
// This is deliberately NOT revocation. Revoking requires a credential more
// privileged than the one that leaked, which would make nox a holder of admin
// credentials for every provider in the stack and a better target than the leak
// it defends against. See docs/usage.md.
//
// TWO PROPERTIES HOLD THIS FEATURE TOGETHER, and both are enforced by tests:
//
//  1. ENDPOINTS ARE COMPILED IN. Verification transmits a live credential to a
//     third party, which is defensible only because that party is the issuer.
//     A configurable endpoint would make `--verify-secrets` an exfiltration
//     primitive built into a security scanner: point it at a host you control
//     and every secret in the repository is delivered to you. There is no flag,
//     config key or environment variable that redirects these.
//
//  2. THE SECRET NEVER APPEARS IN OUTPUT. Not in a log line, a message, or a
//     report. The point is to report that a credential works, not to reproduce
//     it somewhere new.
//
// nox does not keep secrets in findings.json — a finding carries a file and a
// column range, nothing more — so verification re-reads the file at the
// recorded location. That keeps findings.json shareable, which is worth not
// losing.

type validity int

const (
	validityUnknown validity = iota
	validityLive
	validityDead
)

func (v validity) String() string {
	switch v {
	case validityLive:
		return "LIVE"
	case validityDead:
		return "revoked"
	}
	return "unknown"
}

var verifyClient = &http.Client{Timeout: 15 * time.Second}

// extractSecretAt re-reads the literal a finding points at.
//
// Returns an error rather than a best guess when the location does not fit the
// file: a stale scan, or a file edited since, would otherwise have whatever text
// now occupies those columns sent to a third party as if it were the secret.
func extractSecretAt(path string, line, startCol, endCol int) (string, error) {
	if line < 1 || startCol < 1 || endCol < startCol {
		return "", fmt.Errorf("invalid location %s:%d:%d-%d", path, line, startCol, endCol)
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 8<<20)
	for n := 1; sc.Scan(); n++ {
		if n != line {
			continue
		}
		text := sc.Text()
		if startCol > len(text) || endCol > len(text)+1 {
			return "", fmt.Errorf("%s:%d has %d columns, finding names %d-%d", path, line, len(text), startCol, endCol)
		}
		return text[startCol-1 : endCol-1], nil
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("%s has fewer than %d lines", path, line)
}

// verifyGitHubToken asks GitHub whether a token still authenticates.
//
// GET /user is the cheapest authenticated call: 200 means the credential works,
// 401 means it does not. Anything else — rate limiting, an outage — is NOT
// evidence in either direction and must report unknown. Reporting "revoked" on
// a 403 would tell someone a live, public credential is safe to ignore.
//
// The base URL parameter exists for tests. It is not reachable from any flag or
// configuration; callers in production pass githubAPI.
func verifyGitHubToken(token, base string) (result validity, detail string) {
	if base == "" {
		base = githubAPI
	}
	req, err := http.NewRequest(http.MethodGet, base+"/user", http.NoBody)
	if err != nil {
		return validityUnknown, "could not build request"
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "nox (+https://github.com/nox-hq/nox)")

	resp, err := verifyClient.Do(req)
	if err != nil {
		// Deliberately not %w or %v on anything holding the token: a URL error
		// can carry the request, and the request carries the credential.
		return validityUnknown, "could not reach the GitHub API"
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))

	switch resp.StatusCode {
	case http.StatusOK:
		return validityLive, "authenticates against the GitHub API"
	case http.StatusUnauthorized:
		return validityDead, "rejected by the GitHub API"
	default:
		return validityUnknown, fmt.Sprintf("GitHub API answered HTTP %d — not evidence either way", resp.StatusCode)
	}
}

// githubAPI is compiled in. See property (1) in the file comment: this must not
// become configurable.
const githubAPI = "https://api.github.com"

// verifiableRules maps a rule to the provider that can confirm its findings.
// Only rules whose pattern identifies a single issuer belong here — a generic
// "high entropy string" rule has nobody to ask.
var verifiableRules = map[string]string{
	"SEC-003": "github",
	"SEC-213": "github",
	"SEC-435": "github",
	"SEC-495": "github",
	"SEC-496": "github",
}

// verifySecret dispatches to the issuer for a rule nox knows how to check.
func verifySecret(ruleID, secret string) (result validity, detail string) {
	if verifiableRules[ruleID] == "github" {
		return verifyGitHubToken(secret, "")
	}
	return validityUnknown, "no verifier for this rule"
}

// redactedPrefix renders a secret for human output without reproducing enough
// of it to be useful. Kept short deliberately: the first few characters of a
// GitHub token are a fixed provider prefix and carry no entropy.
func redactedPrefix(secret string) string {
	if i := strings.IndexByte(secret, '_'); i > 0 && i < 6 {
		return secret[:i+1] + "…"
	}
	if len(secret) > 4 {
		return secret[:4] + "…"
	}
	return "…"
}

// runVerifySecrets is the `nox verify-secrets` entry point.
//
// Opt-in as a separate command rather than a scan flag, because it does
// something a scan never does: sends a credential over the network. That should
// require typing, not inherit from a habit.
func runVerifySecrets(args []string) int {
	fs := flag.NewFlagSet("verify-secrets", flag.ContinueOnError)
	var inputPath, root string
	fs.StringVar(&inputPath, "input", "findings.json", "path to findings.json from a previous scan")
	fs.StringVar(&root, "root", ".", "directory the scan was run against, used to resolve finding paths")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	raw, err := os.ReadFile(inputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: reading %s: %v\n", inputPath, err)
		return 2
	}
	var doc struct {
		Findings []findings.Finding `json:"findings"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		fmt.Fprintf(os.Stderr, "error: parsing %s: %v\n", inputPath, err)
		return 2
	}

	var checked, live int
	var unverifiable int
	for i := range doc.Findings {
		f := &doc.Findings[i]
		if verifiableRules[f.RuleID] == "" {
			if strings.HasPrefix(f.RuleID, "SEC-") {
				unverifiable++
			}
			continue
		}
		path := f.Location.FilePath
		if !filepath.IsAbs(path) {
			path = filepath.Join(root, path)
		}
		secret, err := extractSecretAt(path, f.Location.StartLine, f.Location.StartColumn, f.Location.EndColumn)
		if err != nil {
			fmt.Printf("  %-8s %-30s could not re-read the secret: %v\n", f.RuleID, f.Location.FilePath, err)
			continue
		}
		checked++
		v, detail := verifySecret(f.RuleID, secret)
		if v == validityLive {
			live++
		}
		fmt.Printf("  %-8s %-30s %-8s %s (%s)\n",
			f.RuleID, fmt.Sprintf("%s:%d", f.Location.FilePath, f.Location.StartLine),
			v, detail, redactedPrefix(secret))
	}

	fmt.Printf("\nchecked %d credential(s); %d still authenticate\n", checked, live)
	if unverifiable > 0 {
		fmt.Printf("%d secret finding(s) have no issuer nox can ask — detection only\n", unverifiable)
	}
	// A live credential in a repository is already public. Exit non-zero so a
	// pipeline can act on it without parsing output.
	if live > 0 {
		fmt.Println("\nA live credential in version control is compromised. Rotate it at the provider;")
		fmt.Println("removing the file does not invalidate the key.")
		return 1
	}
	return 0
}
