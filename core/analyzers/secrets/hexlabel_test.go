package secrets

import (
	"context"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/findings"
)

// SEC-163 had no true-positive control anywhere in this repository — no
// nox-expect line in any of the 19 precision suites, no fixture, nothing. A
// rule with no recall control can be narrowed to silence and every test still
// passes, so the recall cases below are as load-bearing as the refutations.
//
// Measured 2026-09-12 across the rule-diff corpus, SEC-163 produced 122
// findings and 117 of them were the value of a JSON field named `md5` in two
// generated test fixtures in metosin/reitit.

// scanRuleIDs runs the full analyzer — engine, dedup and every refiner — over
// one file. It goes through ScanArtifacts rather than ScanFile because the
// refutations under test live in the refiner loop, and ScanFile stops at the
// engine.
func scanRuleIDs(t *testing.T, path, body string) []string {
	t.Helper()
	dir := t.TempDir()
	abs := writeFile(t, dir, path, body)
	fs, err := NewAnalyzer().ScanArtifacts(context.Background(), []discovery.Artifact{
		{Path: path, AbsPath: abs, Type: discovery.Source, Size: int64(len(body))},
	})
	if err != nil {
		t.Fatalf("ScanArtifacts(%s): %v", path, err)
	}
	var out []string
	for _, f := range fs.Findings() {
		out = append(out, f.RuleID)
	}
	return out
}

func hasRule(ids []string, want string) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}

// userRecord is the measured shape, reduced to one record. Every element is
// load-bearing: `"password"` is what satisfies require_context, `"salt"` sits
// between it and the digest so the hint is neither adjacent nor far away, and
// the md5 is the value actually reported.
const userRecord = `{"user":{"password":"buffy","salt":"UKfGRyKe",` +
	`"md5":"ff252d31f9d6a7e19f2b28521aa1f367"}}`

// gistURL is the aws-cloudformation-templates shape: a bash script folded into
// one CloudFormation `Fn::Sub` scalar, with `privateKeyPath` elsewhere in the
// same scalar doing the authorising.
const gistURL = "UserData:\n  Fn::Sub: \"curl -o gg.sh " +
	"https://gist.github.com/acme/fa21ca796c3a2e0dfe8224934b7b055c" +
	"\\nprivateKeyPath=/etc/pki\\n\"\n"

// TestADigestLabelledHexValueIsNotAKey is the measured case, 117 of the 122.
func TestADigestLabelledHexValueIsNotAKey(t *testing.T) {
	if ids := scanRuleIDs(t, "users.json", userRecord); hasRule(ids, "SEC-163") {
		t.Errorf("SEC-163 reported an md5 digest as a possible secret key; the "+
			"`password` field four keys to its left authorised it. got %v", ids)
	}
}

// TestAHexRunInAURLPathIsNotAKey is the other measured case, 4 of the 122.
func TestAHexRunInAURLPathIsNotAKey(t *testing.T) {
	if ids := scanRuleIDs(t, "cfn.yaml", gistURL); hasRule(ids, "SEC-163") {
		t.Errorf("SEC-163 reported a gist id inside a URL as a possible secret key; "+
			"got %v", ids)
	}
}

// TestAWindowInsideADigestInheritsItsLabel. SEC-696's pattern is
// `[a-zA-Z0-9]{32}`, so on reitit's 64-character sha256 values it matched the
// second half as well — a candidate whose left neighbour is hex, not a key.
// Measured: 2 of the 3 SEC-696 findings left in reitit after #633 were exactly
// this.
func TestAWindowInsideADigestInheritsItsLabel(t *testing.T) {
	const line = `  "sha256":"23de8670a449aaa2c307ac95e5adc1b14d3c3f63d7f3233d807e093ebd813a1e"`
	f := &findings.Finding{}
	f.Location.StartLine, f.Location.EndLine = 1, 1
	f.Location.StartColumn = strings.Index(line, "4d3c3f63") + 1
	f.Location.EndColumn = f.Location.StartColumn + 32
	if !isLabelledDigest([]byte(line+"\n"), f) {
		t.Error("the second 32 characters of a sha256 were not recognised as part of " +
			"the digest; the label belongs to the run, not to the window cut out of it")
	}
}

// TestARealHexKeyStillFires is the recall control, and the reason the fix is a
// label check rather than a threshold change.
//
// Raising the threshold was tried first and measured: with require_context set,
// the context boost is taken as well, so SEC-163's declared 3.5 runs at 3.0.
// Charging the declared value instead removed three Ceph admin keys from
// kubernetes/examples through SEC-162, the sibling rule on the same matcher —
// `key: QVFEQ1pMdFhPUnQrSmhBQUFYaERWNHJsZ3BsMmNjcDR6RFZST0E9PQ==` is a real
// hardcoded credential, and the 5.2/4.7 pair was chosen knowing the discount
// applied. So the threshold stays and the label decides.
func TestARealHexKeyStillFires(t *testing.T) {
	for _, tc := range []struct{ name, path, body string }{
		{"python assignment", "conf.py",
			"SECRET_TOKEN = \"3f5b8c1d9e7a2064b8d3f1e5c7a90b2d\"\n"},
		{"python bytes literal", "conf.py",
			"signing_key = b\"7c1e93a5f0b284d6e9a3c5178b0d4f26\"\n"},
		{"json field", "app.json",
			"{\n  \"apiKey\": \"3f5b8c1d9e7a2064b8d3f1e5c7a90b2d\"\n}\n"},
		{"header directive", "hdr.conf",
			"proxy_set_header X-Api-Key 0c39ef1320ec7f799065f3b3385a2f4e;\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if ids := scanRuleIDs(t, tc.path, tc.body); !hasRule(ids, "SEC-163") {
				t.Errorf("SEC-163 stopped reporting a hex secret written as %s; the "+
					"refutation is wider than the false positives it was measured on. got %v",
					tc.name, ids)
			}
		})
	}
}

// TestAProviderTokenIsNotTouched. Both refutations are gated on the value being
// entirely hexadecimal, which is what keeps them off the ~700 provider rules: a
// GitHub token labelled `md5`, or sitting in a URL, is still a leaked token.
func TestAProviderTokenIsNotTouched(t *testing.T) {
	const body = "md5 = \"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\"\n" +
		"url = \"https://example.com/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\"\n"
	ids := scanRuleIDs(t, "a.py", body)
	var n int
	for _, id := range ids {
		if id == "SEC-003" {
			n++
		}
	}
	if n != 2 {
		t.Errorf("expected both GitHub tokens to survive a digest label and a URL "+
			"path; got %d SEC-003 in %v", n, ids)
	}
}

// TestACredentialInAURLUserinfoIsNotAPath. `https://user:<hex>@host` puts a
// real credential in a URL, and the only thing separating it from a gist id is
// whether a `/` has closed the authority yet.
func TestACredentialInAURLUserinfoIsNotAPath(t *testing.T) {
	const line = "db_url = \"https://svc:0c39ef1320ec7f799065f3b3385a2f4e@db.internal/\"\n"
	f := &findings.Finding{}
	f.Location.StartLine, f.Location.EndLine = 1, 1
	f.Location.StartColumn = strings.Index(line, "0c39") + 1
	f.Location.EndColumn = f.Location.StartColumn + 32
	if inURLPath([]byte(line), f) {
		t.Error("a credential in a URL's userinfo was refuted as a path segment")
	}
	const path = "docs = \"https://gist.github.com/acme/0c39ef1320ec7f799065f3b3385a2f4e\"\n"
	g := &findings.Finding{}
	g.Location.StartLine, g.Location.EndLine = 1, 1
	g.Location.StartColumn = strings.Index(path, "0c39") + 1
	g.Location.EndColumn = g.Location.StartColumn + 32
	if !inURLPath([]byte(path), g) {
		t.Error("the control failed: a gist id in a URL path was not recognised, so " +
			"the negative above proves nothing")
	}
}

// TestLabelLeftOf states the parsing rules directly, so a later edit that
// breaks one fails here rather than through a scan four layers up.
func TestLabelLeftOf(t *testing.T) {
	for _, tc := range []struct{ line, want string }{
		{`  "md5": "ff252d31f9d6a7e19f2b28521aa1f367"`, "md5"},
		{`    "sha256" : "ff252d31f9d6a7e19f2b28521aa1f367"`, "sha256"},
		{`api_key = "ff252d31f9d6a7e19f2b28521aa1f367"`, "api_key"},
		{`token=b"ff252d31f9d6a7e19f2b28521aa1f367"`, "token"},
		{`X-Api-Key: ff252d31f9d6a7e19f2b28521aa1f367`, "key"},
		{`- md5: ff252d31f9d6a7e19f2b28521aa1f367`, "md5"},
		{`checksum => "ff252d31f9d6a7e19f2b28521aa1f367"`, "checksum"},
		// Unlabelled: a bare value in a list, and one in a URL.
		{`  - ff252d31f9d6a7e19f2b28521aa1f367`, ""},
		{`https://gist.github.com/acme/ff252d31f9d6a7e19f2b28521aa1f367`, ""},
	} {
		col := strings.Index(tc.line, "ff252d31") + 1
		if col == 0 {
			t.Fatalf("fixture has no value: %q", tc.line)
		}
		if got := labelLeftOf(tc.line, col); got != tc.want {
			t.Errorf("labelLeftOf(%q) = %q, want %q", tc.line, got, tc.want)
		}
	}
}

// TestARefutationNeedsTheValueToBeHex guards the gate itself at the unit level:
// a non-hex value reaches neither check regardless of how it is labelled.
func TestARefutationNeedsTheValueToBeHex(t *testing.T) {
	const line = "md5 = \"xK9mR3pZqW7vT2nL5sH8dF4gJ6bC0aYe\"\n"
	f := &findings.Finding{}
	f.Location.StartLine, f.Location.EndLine = 1, 1
	f.Location.StartColumn = strings.Index(line, "xK9") + 1
	f.Location.EndColumn = f.Location.StartColumn + len("xK9mR3pZqW7vT2nL5sH8dF4gJ6bC0aYe")
	if isLabelledDigest([]byte(line), f) {
		t.Error("a non-hex value labelled md5 was refuted as a digest; the hex gate " +
			"is what keeps this off the provider rules")
	}
}
