package data

import (
	"strings"
	"testing"
)

// These tests pin the precision fix for DATA-005 and DATA-001 from both sides.
//
// The recall side matters most and comes first in each pair: a precision fix
// that quietly guts the rule is worse than the false positives it removed, so
// every "must still fire" case is asserted before any "must not fire" case.
//
// They go through the analyzer, not the predicate function, so they fail if
// the predicate is correct but never wired into the rule — which is the way
// this fix is most likely to be lost in a future refactor.

// scanFires reports whether scanning content produces a finding for ruleID.
func scanFires(t *testing.T, a *Analyzer, ruleID, content string) bool {
	t.Helper()
	results, err := a.ScanFile("config.yaml", []byte(content))
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	for i := range results {
		if results[i].RuleID == ruleID {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// DATA-005 — recall: genuinely public addresses must still be reported
// ---------------------------------------------------------------------------

// TestDATA005_PublicAddressesStillFire is the recall guard. Every address here
// is publicly routable and hardcoding it in configuration is the disclosure
// DATA-005 exists to catch (CWE-200). If this test goes quiet, the rule has
// been suppressed rather than fixed.
func TestDATA005_PublicAddressesStillFire(t *testing.T) {
	a := NewAnalyzer()

	tests := []struct {
		name    string
		content string
	}{
		{"public DNS resolver", "server = '8.8.8.8'\n"},
		{"cloudflare resolver", "ip: 1.1.1.1\n"},
		{"quad9 resolver", "addr = \"9.9.9.9\"\n"},
		{"arbitrary public host", "host: 93.184.216.34\n"},
		{"just below the private block", "ip = 9.255.255.255\n"},
		{"just above the private block", "ip = 11.0.0.0\n"},
		{"just below 172.16/12", "server: 172.15.255.255\n"},
		{"just above 172.16/12", "server: 172.32.0.0\n"},
		{"just below 192.168/16", "addr: 192.167.255.255\n"},
		{"just above 192.168/16", "addr: 192.169.0.0\n"},
		{"just below CGNAT", "host = 100.63.255.255\n"},
		{"just above CGNAT", "host = 100.128.0.0\n"},
		{"just below TEST-NET-1", "ip = 192.0.1.255\n"},
		{"just above TEST-NET-1", "ip = 192.0.3.0\n"},
		{"just below TEST-NET-2", "ip = 198.51.99.255\n"},
		{"just above TEST-NET-2", "ip = 198.51.101.0\n"},
		{"just below TEST-NET-3", "ip = 203.0.112.255\n"},
		{"just above TEST-NET-3", "ip = 203.0.114.0\n"},
		{"just below multicast", "ip = 223.255.255.255\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !scanFires(t, a, "DATA-005", tt.content) {
				t.Fatalf("DATA-005 must still fire on a public address: %q", strings.TrimSpace(tt.content))
			}
		})
	}
}

// ---------------------------------------------------------------------------
// DATA-005 — precision: non-public and reserved space must stay silent
// ---------------------------------------------------------------------------

// TestDATA005_NonPublicRanges covers every range the rule must exclude. Each
// case is a value a developer writes on purpose: a loopback bind address, an
// RFC 1918 service host, an RFC 5737 address in a sample config. Before the
// fix the pattern matched every dotted quad, so all of these were reported as
// a "public IP address".
func TestDATA005_NonPublicRanges(t *testing.T) {
	a := NewAnalyzer()

	tests := []struct {
		name    string
		content string
	}{
		// RFC 1122 "this network" / unspecified.
		{"unspecified bind address", "host: 0.0.0.0\n"},
		{"this-network", "ip = 0.1.2.3\n"},
		// RFC 1122 loopback.
		{"loopback", "host: 127.0.0.1\n"},
		{"loopback elsewhere in /8", "server = '127.255.255.254'\n"},
		// RFC 1918 private.
		{"private 10/8", "server: 10.0.0.5\n"},
		{"private 172.16/12 low", "addr = 172.16.0.1\n"},
		{"private 172.16/12 high", "addr = 172.31.255.254\n"},
		{"private 192.168/16", "addr: 192.168.1.1\n"},
		// RFC 3927 link-local.
		{"link-local", "ip = 169.254.169.254\n"},
		// RFC 6598 carrier-grade NAT.
		{"cgnat low", "host = 100.64.0.1\n"},
		{"cgnat high", "host = 100.127.255.254\n"},
		// RFC 6890 IETF protocol assignments.
		{"protocol assignments", "ip: 192.0.0.8\n"},
		// RFC 5737 documentation ranges — reserved so docs and tests can use them.
		{"TEST-NET-1", "server = '192.0.2.1'\n"},
		{"TEST-NET-2", "server = '198.51.100.42'\n"},
		{"TEST-NET-3", "server = '203.0.113.9'\n"},
		// RFC 7526 6to4 relay anycast (deprecated).
		{"6to4 relay anycast", "ip = 192.88.99.1\n"},
		// RFC 2544 benchmarking.
		{"benchmarking", "host: 198.19.0.1\n"},
		// RFC 5771 multicast.
		{"multicast low", "addr = 224.0.0.1\n"},
		{"multicast high", "addr = 239.255.255.255\n"},
		// RFC 1112 reserved, including the broadcast address.
		{"reserved 240/4", "ip = 240.0.0.1\n"},
		{"limited broadcast", "ip = 255.255.255.255\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if scanFires(t, a, "DATA-005", tt.content) {
				t.Fatalf("DATA-005 must not fire on a non-public address: %q", strings.TrimSpace(tt.content))
			}
		})
	}
}

// TestDATA005_UnparseableCandidate pins the drop-on-parse-failure behaviour.
// The pattern's octet alternation admits a leading-zero form that netip
// rejects; nox cannot claim such a value is public, so it stays silent rather
// than guessing.
func TestDATA005_UnparseableCandidate(t *testing.T) {
	a := NewAnalyzer()
	if scanFires(t, a, "DATA-005", "ip = 008.008.008.008\n") {
		t.Fatal("DATA-005 must not fire on an address netip cannot parse")
	}
}

// TestIsPublicIPv4Match_Extraction pins how the predicate picks the address
// out of the match text, independently of what today's pattern can produce.
//
// The address is the LAST dotted quad in the match, because the key can carry
// digits while nothing follows the address. DATA-005's current pattern will
// not match a key like `ip2`, so the multi-quad case is unreachable through it
// — the predicate is asserted directly so a future pattern widening does not
// silently start reading the wrong number.
func TestIsPublicIPv4Match_Extraction(t *testing.T) {
	tests := []struct {
		name  string
		match string
		want  bool
	}{
		{"no address at all", "host = ", false},
		{"trailing address wins — public", "10.0.0.5_ip = 8.8.8.8", true},
		{"trailing address wins — private", "8.8.8.8_ip = 10.0.0.5", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isPublicIPv4Match(tt.match); got != tt.want {
				t.Fatalf("isPublicIPv4Match(%q) = %v, want %v", tt.match, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// DATA-001 — recall: real addresses must still be reported
// ---------------------------------------------------------------------------

// TestDATA001_RealAddressesStillFire is the recall guard for the email rule.
// Every address here is at an ordinary registrable domain and is exactly the
// hardcoded PII DATA-001 exists to catch.
func TestDATA001_RealAddressesStillFire(t *testing.T) {
	a := NewAnalyzer()

	tests := []struct {
		name    string
		content string
	}{
		{"corporate address", "admin_email = jane.doe@acmecorp.io\n"},
		{"quoted address", "owner: \"j.smith@northwind-logistics.co.uk\"\n"},
		{"gmail address", "contact = 'someone.real@gmail.com'\n"},
		{"plus addressing", "notify: alerts+prod@acmecorp.io\n"},
		// The reserved names are reserved as domains, not as substrings: a
		// domain that merely contains "example" or ends in "testing" is a real
		// registrable domain and must still be reported.
		{"example as a label prefix", "email = ops@example-corp.com\n"},
		{"reserved TLD as a suffix fragment", "email = ops@acmecorp.contest\n"},
		{"reserved domain as a suffix fragment", "email = ops@notexample.com\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !scanFires(t, a, "DATA-001", tt.content) {
				t.Fatalf("DATA-001 must still fire on a real address: %q", strings.TrimSpace(tt.content))
			}
		})
	}
}

// ---------------------------------------------------------------------------
// DATA-001 — precision: RFC-reserved documentation addresses stay silent
// ---------------------------------------------------------------------------

// TestDATA001_ReservedDomains covers the domains and TLDs that RFC 2606 and
// RFC 6761 reserve so documentation, examples and tests have an address to
// use. Writing one of these is the correct thing for a developer to do, so
// reporting it as leaked PII is always a false positive.
func TestDATA001_ReservedDomains(t *testing.T) {
	a := NewAnalyzer()

	tests := []struct {
		name    string
		content string
	}{
		// RFC 2606 §3 reserved second-level domains.
		{"example.com", "email = user@example.com\n"},
		{"example.net", "email = user@example.net\n"},
		{"example.org", "email = user@example.org\n"},
		{"subdomain of example.com", "email = noreply@mail.example.com\n"},
		{"uppercase example.com", "email = User@Example.COM\n"},
		{"fully qualified example.com", "email = user@example.com.\n"},
		// RFC 2606 §2 / RFC 6761 reserved TLDs.
		{".example TLD", "email = user@myapp.example\n"},
		{".test TLD", "email = user@myapp.test\n"},
		{".invalid TLD", "email = user@myapp.invalid\n"},
		{".localhost TLD", "email = user@myapp.localhost\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if scanFires(t, a, "DATA-001", tt.content) {
				t.Fatalf("DATA-001 must not fire on an RFC-reserved address: %q", strings.TrimSpace(tt.content))
			}
		})
	}
}

// TestIsReportableEmailMatch_Degenerate covers the predicate's guards for
// match text that carries no usable domain. Unreachable through the current
// pattern, which requires an "@" and a dotted domain, but the predicate must
// not depend on that.
func TestIsReportableEmailMatch_Degenerate(t *testing.T) {
	for _, match := range []string{"= nobody", `= user@""`} {
		if isReportableEmailMatch(match) {
			t.Fatalf("a match with no domain must not be reported: %q", match)
		}
	}
}
