package hardening

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/findings"
)

// scanSource runs the analyzer over a single synthetic file.
func scanSource(t *testing.T, name, content string) []findings.Finding {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, filepath.Base(name))
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	fs, err := (&Analyzer{}).ScanArtifacts(context.Background(),
		[]discovery.Artifact{{Path: name, AbsPath: p}})
	if err != nil {
		t.Fatal(err)
	}
	return fs.Findings()
}

// only asserts that a source produced exactly one finding of the given rule and
// returns it, so a case can go on to check severity or confidence.
func only(t *testing.T, ruleID, src string) findings.Finding {
	t.Helper()
	got := scanSource(t, "a.go", src)
	if len(got) != 1 || got[0].RuleID != ruleID {
		t.Fatalf("want exactly one %s, got %d findings %v for:\n%s",
			ruleID, len(got), ruleIDs(got), src)
	}
	return got[0]
}

func ruleIDs(fs []findings.Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.RuleID)
	}
	return out
}

func TestFlagsInsecureSkipVerify(t *testing.T) {
	for name, src := range map[string]string{
		"composite literal": `package m
import "crypto/tls"
func f() *tls.Config { return &tls.Config{InsecureSkipVerify: true} }`,

		"value literal": `package m
import "crypto/tls"
func f() tls.Config { return tls.Config{InsecureSkipVerify: true} }`,

		// The shape that actually appears in the wild: the config is nested in
		// the transport that uses it.
		"nested in http.Transport": `package m
import ("crypto/tls"; "net/http")
func f() *http.Transport {
	return &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
}`,

		// Set after construction. This is how the setting is most often slipped
		// in later, and a rule that only looked at composite literals would
		// miss it entirely.
		"assignment after construction": `package m
import "crypto/tls"
func f() *tls.Config {
	c := &tls.Config{MinVersion: tls.VersionTLS12}
	c.InsecureSkipVerify = true
	return c
}`,

		"aliased import": `package m
import cryptotls "crypto/tls"
func f() *cryptotls.Config { return &cryptotls.Config{InsecureSkipVerify: true} }`,

		// The element type is declared once by the slice, so the inner literal
		// carries no type of its own.
		"slice element with elided type": `package m
import "crypto/tls"
func f() []tls.Config { return []tls.Config{{InsecureSkipVerify: true}} }`,
	} {
		t.Run(name, func(t *testing.T) {
			f := only(t, ruleInsecureSkipVerify, src)
			// High is the whole point: the fleet gate this rule exists for
			// fails on net-new critical/high only, so a lower severity would
			// make the rule decorative.
			if f.Severity != findings.SeverityHigh {
				t.Errorf("severity = %s, want high", f.Severity)
			}
			if f.Metadata["cwe"] != "CWE-295" {
				t.Errorf("cwe = %q, want CWE-295", f.Metadata["cwe"])
			}
		})
	}
}

// The negative half of the rule. Every case here is code that a pattern-match
// on the field name would report and that is not a vulnerability. A rule that
// fires on these is worse than no rule: it gets suppressed wholesale, and then
// the true positives go with it.
func TestDoesNotFlagSafeOrUnprovableForms(t *testing.T) {
	for name, src := range map[string]string{
		"explicitly false": `package m
import "crypto/tls"
func f() *tls.Config { return &tls.Config{InsecureSkipVerify: false} }`,

		"assigned false": `package m
import "crypto/tls"
func f(c *tls.Config) { c.InsecureSkipVerify = false }`,

		// KNOWN LIMITS (1): the value is not resolvable from the AST, so it is
		// not reported. This test pins that decision so it cannot be changed
		// silently — reporting here would fire on every config-driven client.
		"variable value": `package m
import "crypto/tls"
func f(skip bool) *tls.Config { return &tls.Config{InsecureSkipVerify: skip} }`,

		"computed value": `package m
import ("crypto/tls"; "os")
func f() *tls.Config { return &tls.Config{InsecureSkipVerify: os.Getenv("DEV") == "1"} }`,

		"value from a call": `package m
import "crypto/tls"
func skip() bool { return true }
func f() *tls.Config { return &tls.Config{InsecureSkipVerify: skip()} }`,

		"value forwarded from another struct": `package m
import "crypto/tls"
type opts struct{ InsecureSkipVerify bool }
func f(o opts) *tls.Config { return &tls.Config{InsecureSkipVerify: o.InsecureSkipVerify} }`,

		// Real code contains exactly this: grpc's xds credentials carry the
		// comment "InsecureSkipVerify needs to be set to true because ...".
		"line comment": `package m
import "crypto/tls"
// InsecureSkipVerify: true would disable verification; do not do it.
func f() *tls.Config { return &tls.Config{} }`,

		"block comment": `package m
/*
	c.InsecureSkipVerify = true
*/
func f() {}`,

		"string literal": `package m
const doc = "InsecureSkipVerify: true"`,

		"struct field declaration": `package m
type config struct {
	// InsecureSkipVerify disables verification when true.
	InsecureSkipVerify bool
}`,

		"read, not written": `package m
import ("crypto/tls"; "fmt")
func f(c *tls.Config) { fmt.Println(c.InsecureSkipVerify) }`,
	} {
		t.Run(name, func(t *testing.T) {
			if got := scanSource(t, "a.go", src); len(got) != 0 {
				t.Errorf("got %d findings %v, want 0 for:\n%s", len(got), ruleIDs(got), src)
			}
		})
	}
}

func TestFlagsWeakTLSVersion(t *testing.T) {
	for name, src := range map[string]string{
		"TLS 1.0 constant": `package m
import "crypto/tls"
func f() *tls.Config { return &tls.Config{MinVersion: tls.VersionTLS10} }`,

		"TLS 1.1 constant": `package m
import "crypto/tls"
func f() *tls.Config { return &tls.Config{MinVersion: tls.VersionTLS11} }`,

		"SSL 3.0 constant": `package m
import "crypto/tls"
func f() *tls.Config { return &tls.Config{MinVersion: tls.VersionSSL30} }`,

		"raw hex inside a tls.Config": `package m
import "crypto/tls"
func f() *tls.Config { return &tls.Config{MinVersion: 0x0301} }`,

		"raw decimal inside a tls.Config": `package m
import "crypto/tls"
func f() *tls.Config { return &tls.Config{MinVersion: 770} }`,

		// Taken from real code: thrift's socket helper does exactly this.
		"assignment of a tls constant": `package m
import "crypto/tls"
func f(c *tls.Config) {
	if c.MinVersion == 0 {
		c.MinVersion = tls.VersionTLS10
	}
}`,
	} {
		t.Run(name, func(t *testing.T) {
			f := only(t, ruleWeakTLSVersion, src)
			// Medium, deliberately: the peer is still authenticated, and a
			// legacy floor is sometimes a defensible decision. See the rule
			// comment for why inflating this to High would devalue High.
			if f.Severity != findings.SeverityMedium {
				t.Errorf("severity = %s, want medium", f.Severity)
			}
		})
	}
}

func TestDoesNotFlagAcceptableTLSVersions(t *testing.T) {
	for name, src := range map[string]string{
		"TLS 1.2": `package m
import "crypto/tls"
func f() *tls.Config { return &tls.Config{MinVersion: tls.VersionTLS12} }`,

		"TLS 1.3": `package m
import "crypto/tls"
func f() *tls.Config { return &tls.Config{MinVersion: tls.VersionTLS13} }`,

		"MaxVersion is not MinVersion": `package m
import "crypto/tls"
func f() *tls.Config { return &tls.Config{MaxVersion: tls.VersionTLS10, MinVersion: tls.VersionTLS12} }`,

		// MinVersion is a generic field name. A bare integer only means a TLS
		// version inside something known to be a tls.Config; anywhere else it
		// is an API version, a schema revision, or a protocol number.
		"unrelated struct with a MinVersion field": `package m
type api struct{ MinVersion int }
func f() api { return api{MinVersion: 0x0301} }`,

		"unrelated assignment of a raw number": `package m
type api struct{ MinVersion int }
func f(a *api) { a.MinVersion = 769 }`,

		"variable version": `package m
import "crypto/tls"
func f(v uint16) *tls.Config { return &tls.Config{MinVersion: v} }`,
	} {
		t.Run(name, func(t *testing.T) {
			if got := scanSource(t, "a.go", src); len(got) != 0 {
				t.Errorf("got %d findings %v, want 0 for:\n%s", len(got), ruleIDs(got), src)
			}
		})
	}
}

// Confidence separates "the AST proved this is a crypto/tls.Config" from "the
// field name says so and nothing else does". Both are reported; a reviewer can
// tell them apart.
func TestConfidenceReflectsTypeConfirmation(t *testing.T) {
	confirmed := only(t, ruleInsecureSkipVerify, `package m
import "crypto/tls"
func f() *tls.Config { return &tls.Config{InsecureSkipVerify: true} }`)
	if confirmed.Confidence != findings.ConfidenceHigh {
		t.Errorf("confirmed tls.Config confidence = %s, want high", confirmed.Confidence)
	}

	// A wrapper struct with its own InsecureSkipVerify field: reported,
	// because a Go field with that name set to true has one meaning and such
	// wrappers pass it straight through to crypto/tls — but the type is not
	// proven without go/types, so confidence drops.
	wrapper := only(t, ruleInsecureSkipVerify, `package m
type clientOpts struct{ InsecureSkipVerify bool }
func f() clientOpts { return clientOpts{InsecureSkipVerify: true} }`)
	if wrapper.Confidence != findings.ConfidenceMedium {
		t.Errorf("unconfirmed struct confidence = %s, want medium", wrapper.Confidence)
	}
	if !strings.Contains(wrapper.Message, "could not be confirmed") {
		t.Errorf("message %q does not say the type is unconfirmed", wrapper.Message)
	}
}

// KNOWN LIMITS (2). gosec flags test files; this does not. Tests legitimately
// dial httptest servers with self-signed certificates, and a High finding on
// every such test would either block legitimate PRs or teach the team to
// suppress HARDEN-001 outright.
func TestSkipsTestCode(t *testing.T) {
	src := `package m
import "crypto/tls"
func f() *tls.Config { return &tls.Config{InsecureSkipVerify: true} }`
	for _, name := range []string{"a_test.go", "testdata/a.go", "core/testdata/a.go"} {
		if got := scanSource(t, name, src); len(got) != 0 {
			t.Errorf("%s: got %d findings, want 0 (test code)", name, len(got))
		}
	}
}

func TestSkipsNonGoFiles(t *testing.T) {
	for _, name := range []string{"notes.md", "config.yaml", "app.py"} {
		if got := scanSource(t, name, "InsecureSkipVerify: true"); len(got) != 0 {
			t.Errorf("%s: got %d findings, want 0", name, len(got))
		}
	}
}

// A file that does not compile still yields a partial AST. Degrading to silence
// here would mean a scan of a work-in-progress branch quietly reports nothing.
func TestPartialParseStillReports(t *testing.T) {
	src := `package m
import "crypto/tls"
func f() *tls.Config { return &tls.Config{InsecureSkipVerify: true}` // unclosed
	if got := scanSource(t, "a.go", src); len(got) != 1 {
		t.Errorf("got %d findings, want 1 from a partial parse", len(got))
	}
}

func TestBothFieldsInOneConfigReportSeparately(t *testing.T) {
	got := scanSource(t, "a.go", `package m
import "crypto/tls"
func f() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10}
}`)
	if len(got) != 2 {
		t.Fatalf("got %d findings %v, want 2", len(got), ruleIDs(got))
	}
	seen := map[string]bool{}
	for _, f := range got {
		seen[f.RuleID] = true
	}
	if !seen[ruleInsecureSkipVerify] || !seen[ruleWeakTLSVersion] {
		t.Errorf("want both rules, got %v", ruleIDs(got))
	}
}

func TestRulesAreRegistered(t *testing.T) {
	byID := map[string]bool{}
	for _, r := range (&Analyzer{}).Rules().Rules() {
		byID[r.ID] = true
		switch r.ID {
		case ruleInsecureSkipVerify:
			if r.Severity != findings.SeverityHigh {
				t.Errorf("%s severity = %s, want high", r.ID, r.Severity)
			}
			if r.Metadata["cwe"] != "CWE-295" {
				t.Errorf("%s cwe = %q, want CWE-295", r.ID, r.Metadata["cwe"])
			}
		case ruleWeakTLSVersion:
			if r.Severity != findings.SeverityMedium {
				t.Errorf("%s severity = %s, want medium", r.ID, r.Severity)
			}
		default:
			t.Errorf("unexpected rule %s", r.ID)
		}
		if r.Remediation == "" || len(r.References) == 0 {
			t.Errorf("%s is missing remediation or references", r.ID)
		}
	}
	if !byID[ruleInsecureSkipVerify] || !byID[ruleWeakTLSVersion] {
		t.Errorf("missing rules, got %v", byID)
	}
}

// Files that mention neither option are never parsed. This is the pre-filter
// that keeps the analyzer off the critical path for the ~99% of Go files with
// no TLS configuration in them.
func TestNonTLSFilesAreNotParsed(t *testing.T) {
	if hasTrigger([]byte("package m\nfunc main() {}\n")) {
		t.Error("a file with no TLS option was not filtered out")
	}
	if !hasTrigger([]byte("InsecureSkipVerify")) || !hasTrigger([]byte("MinVersion")) {
		t.Error("a file mentioning a TLS option was filtered out")
	}
}
