package appconfig

import (
	"regexp"

	"github.com/nox-hq/nox/core/findings"
)

// RuleCSRFDisabled (APPCFG-008) reports Spring Security configuration that
// switches CSRF protection off, or off for some routes (CWE-352):
// `.csrf().disable()`, `.csrf(c -> c.disable())`,
// `.csrf(AbstractHttpConfigurer::disable)`, `.csrf(c -> c.ignoringRequestMatchers(...))`.
// A browser that holds the user's session cookie then submits a forged form
// or request to those routes as the user. An API that authenticates every
// request with a bearer token rather than a cookie is not exposed, which is
// why this is reported at medium confidence: the finding is the switch, the
// reader decides whether the routes are reached with a cookie.
const RuleCSRFDisabled = "APPCFG-008"

var csrfRules = []rule{{
	id: RuleCSRFDisabled, cwe: "CWE-352", severity: findings.SeverityMedium,
	confidence:  findings.ConfidenceMedium,
	message:     "CSRF protection is switched off in the Spring Security configuration",
	description: "Spring Security CSRF protection disabled (csrf().disable(), csrf(c -> c.disable()), csrf(AbstractHttpConfigurer::disable)) or exempted for routes (ignoringRequestMatchers / ignoringAntMatchers)",
	remediation: "Keep CSRF protection on for every route a browser reaches with a session cookie; exempt only endpoints authenticated by a bearer token or signature, and say so beside the exemption.",
	tags:        []string{"csrf", "spring", "owasp-a01"},
	patterns: []pattern{
		{langs: java, need: "csrf", re: regexp.MustCompile(`\.\s*csrf\s*\(\s*\)\s*\.\s*(?:disable|ignoring(?:RequestMatchers|AntMatchers))\s*\(`)},
		{langs: java, need: "csrf", re: regexp.MustCompile(`\.\s*csrf\s*\(\s*(?:[\w.]+\s*::\s*disable|\(?\s*\w+\s*\)?\s*->\s*\w+\s*\.\s*(?:disable|ignoring(?:RequestMatchers|AntMatchers))\s*\()`)},
	},
}}
