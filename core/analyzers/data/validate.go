package data

import (
	"net/netip"
	"regexp"
	"strings"
)

// This file holds the post-match predicates for the data-sensitivity rules
// whose regex can only find a *candidate*. The rule pattern says "something
// IP-shaped / email-shaped is assigned here"; the predicate here decides
// whether that particular value is worth reporting.
//
// The split exists because the decisions below are range and suffix
// membership, and RE2 expresses those only as long alternations that nobody
// can check against an RFC afterwards. A netip.Prefix table and a domain list
// can be diffed against the RFC line by line — see rules.Rule.ValidateMatch.

// ---------------------------------------------------------------------------
// DATA-005 — public IPv4 addresses
// ---------------------------------------------------------------------------

// nonPublicIPv4 lists every IPv4 range DATA-005 must stay silent on. The rule
// is titled "Hardcoded public IP address"; anything in this table is not a
// public address, so reporting it contradicts the rule's own description.
//
// Two groups, both non-findings for the same reason — the value is not a
// routable endpoint that leaks infrastructure:
//
//   - Non-routable / special-purpose space (RFC 1918, loopback, link-local,
//     CGNAT, multicast, reserved). `host: 127.0.0.1` and `addr: 10.0.0.5` are
//     the overwhelmingly common case in real configuration, and flagging them
//     is what made this rule mostly noise.
//   - Reserved documentation space (RFC 5737 TEST-NET-1/2/3). These exist
//     precisely so examples, tests and docs have an address to use. Writing
//     192.0.2.1 in a sample config is the correct thing for a developer to do.
//
// Ordered numerically so it reads against the IANA special-purpose registry.
var nonPublicIPv4 = []struct {
	prefix netip.Prefix
	why    string
}{
	{netip.MustParsePrefix("0.0.0.0/8"), `RFC 1122 "this network"`},
	{netip.MustParsePrefix("10.0.0.0/8"), "RFC 1918 private"},
	{netip.MustParsePrefix("100.64.0.0/10"), "RFC 6598 carrier-grade NAT"},
	{netip.MustParsePrefix("127.0.0.0/8"), "RFC 1122 loopback"},
	{netip.MustParsePrefix("169.254.0.0/16"), "RFC 3927 link-local"},
	{netip.MustParsePrefix("172.16.0.0/12"), "RFC 1918 private"},
	{netip.MustParsePrefix("192.0.0.0/24"), "RFC 6890 IETF protocol assignments"},
	{netip.MustParsePrefix("192.0.2.0/24"), "RFC 5737 TEST-NET-1 (documentation)"},
	{netip.MustParsePrefix("192.88.99.0/24"), "RFC 7526 6to4 relay anycast (deprecated)"},
	{netip.MustParsePrefix("192.168.0.0/16"), "RFC 1918 private"},
	{netip.MustParsePrefix("198.18.0.0/15"), "RFC 2544 benchmarking"},
	{netip.MustParsePrefix("198.51.100.0/24"), "RFC 5737 TEST-NET-2 (documentation)"},
	{netip.MustParsePrefix("203.0.113.0/24"), "RFC 5737 TEST-NET-3 (documentation)"},
	{netip.MustParsePrefix("224.0.0.0/4"), "RFC 5771 multicast"},
	{netip.MustParsePrefix("240.0.0.0/4"), "RFC 1112 reserved (includes 255.255.255.255 broadcast)"},
}

// ipv4InMatch pulls the dotted-quad out of a DATA-005 match. The match text is
// the whole `host: 203.0.113.9` assignment, so the address is the last
// IPv4-shaped run in it — "last" because the key can itself contain digits
// (`ip2 = ...`), while nothing follows the address in the pattern.
var ipv4InMatch = regexp.MustCompile(`\d{1,3}(?:\.\d{1,3}){3}`)

// isPublicIPv4Match reports whether a DATA-005 candidate carries a genuinely
// public IPv4 address, and is the rule's ValidateMatch.
//
// A candidate whose address does not parse is dropped rather than reported:
// netip rejects forms real configuration does not use (leading-zero octets,
// out-of-range values), and a value nox cannot resolve to an address is a
// value it cannot claim is public.
//
// IPv4 only, deliberately: DATA-005's pattern is a dotted quad and no rule in
// this analyzer matches IPv6 today, so an IPv6 leg here (RFC 3849's
// 2001:db8::/32 in particular) would be unreachable code guarding a rule that
// does not exist. Add it with the rule.
func isPublicIPv4Match(matchText string) bool {
	candidates := ipv4InMatch.FindAllString(matchText, -1)
	if len(candidates) == 0 {
		return false
	}
	addr, err := netip.ParseAddr(candidates[len(candidates)-1])
	if err != nil || !addr.Is4() {
		return false
	}
	for i := range nonPublicIPv4 {
		if nonPublicIPv4[i].prefix.Contains(addr) {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// DATA-001 — email addresses
// ---------------------------------------------------------------------------

// reservedEmailDomains are the second-level domains RFC 2606 §3 reserves for
// documentation and examples. They resolve to nothing and belong to nobody, so
// an address at one of them is not PII and never was.
var reservedEmailDomains = []string{
	"example.com",
	"example.net",
	"example.org",
}

// reservedEmailTLDs are the top-level domains reserved by RFC 2606 §2 and
// RFC 6761 for testing, examples and local use. Same reasoning: a developer
// writing user@myapp.test is following the standard, not leaking an address.
var reservedEmailTLDs = []string{
	"example",
	"invalid",
	"localhost",
	"test",
}

// isReportableEmailMatch reports whether a DATA-001 candidate names a real
// mailbox rather than a reserved documentation address, and is the rule's
// ValidateMatch.
//
// Subdomains count: RFC 2606 reserves example.com and everything under it, so
// noreply@mail.example.com is excluded on the same grounds as
// noreply@example.com.
func isReportableEmailMatch(matchText string) bool {
	at := strings.LastIndex(matchText, "@")
	if at < 0 {
		return false
	}
	domain := strings.ToLower(strings.Trim(matchText[at+1:], `"' `))
	// A trailing dot is the fully-qualified spelling of the same domain.
	domain = strings.TrimSuffix(domain, ".")
	if domain == "" {
		return false
	}
	for _, d := range reservedEmailDomains {
		if domain == d || strings.HasSuffix(domain, "."+d) {
			return false
		}
	}
	for _, tld := range reservedEmailTLDs {
		if domain == tld || strings.HasSuffix(domain, "."+tld) {
			return false
		}
	}
	local := strings.ToLower(strings.TrimLeft(matchText[:at], "\"'=: \t"))
	return !roleMailboxes[local]
}

// roleMailboxes are local parts that name a function rather than a person.
// DATA-001 is CWE-359, exposure of private personal information, and a role
// mailbox belongs to an organisation wherever it appears: on the 2026-09-27
// head-to-head, support@crewai.com and hello@neatlogs.com alone were 309 of
// the rule's 328 findings. Matched whole, so supporter.jane@ is still a person.
var roleMailboxes = map[string]bool{
	"support": true, "hello": true, "hi": true, "info": true, "contact": true,
	"sales": true, "security": true, "noreply": true, "no-reply": true,
	"donotreply": true, "do-not-reply": true, "admin": true, "team": true,
	"help": true, "helpdesk": true, "press": true, "privacy": true,
	"legal": true, "abuse": true, "postmaster": true, "webmaster": true,
	"hostmaster": true, "feedback": true, "billing": true, "careers": true,
	"jobs": true, "partners": true, "notifications": true, "deploy": true,
	"git": true,
}

// DATA-004 — phone numbers
//
// isReportablePhoneMatch rejects numbers no person has. The North American
// Numbering Plan reserves 555-0100 through 555-0199 for fictional use, which
// is why documentation uses them: on the 2026-09-27 head-to-head, 28 of the
// rule's 32 findings were +1 415 555 0123 in openai-python's API reference.
// The other 4 were 1234567890. A run of consecutive or identical digits is a
// placeholder in the same way.
func isReportablePhoneMatch(matchText string) bool {
	var d []byte
	for i := 0; i < len(matchText); i++ {
		if c := matchText[i]; c >= '0' && c <= '9' {
			d = append(d, c)
		}
	}
	if len(d) < 10 {
		return true
	}
	n := string(d[len(d)-10:])
	if n[3:6] == "555" && n[6:] >= "0100" && n[6:] <= "0199" {
		return false
	}
	return !isDigitRun(n)
}

// isDigitRun reports whether every digit repeats the first, or each is one
// more (or one less) than the one before, wrapping 9 to 0: 5555555555,
// 1234567890, 9876543210.
func isDigitRun(n string) bool {
	same, up, down := true, true, true
	for i := 1; i < len(n); i++ {
		p, c := n[i-1]-'0', n[i]-'0'
		same = same && c == p
		up = up && c == (p+1)%10
		down = down && c == (p+9)%10
	}
	return same || up || down
}

// DATA-003 — payment card numbers
//
// The issuer prefixes (4.., 51-55.., 34/37.., 6011/65..) describe the SHAPE of
// a card number and nothing more. What makes a 16-digit run an actual card is
// the Luhn checksum, which every issued card satisfies and a random digit run
// satisfies about one time in ten.
//
// Measured on the pinned corpus, DATA-003 produced 560 findings and 52 of them
// (9.3%) passed Luhn -- which is the rate you would expect from chance, because
// all 560 were floating-point numbers in embedding vectors and notebook output.
// Luhn alone is therefore necessary and not sufficient; see
// isInsideDecimalLiteral, which removes the rest.
func isPaymentCardNumber(matchText string) bool {
	digits := strings.TrimFunc(matchText, func(r rune) bool { return r < '0' || r > '9' })
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	sum, alt := 0, false
	for i := len(digits) - 1; i >= 0; i-- {
		c := digits[i]
		if c < '0' || c > '9' {
			return false
		}
		d := int(c - '0')
		if alt {
			if d *= 2; d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	return sum%10 == 0
}
