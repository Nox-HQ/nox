package data

import "testing"

// DATA-001 is CWE-359, exposure of private personal information. A role
// mailbox (support@, hello@, noreply@) belongs to an organisation rather than
// a person wherever it appears, and on the 2026-09-27 head-to-head two of them
// were 309 of the rule's 328 findings: support@crewai.com in OpenAPI contact
// blocks and hello@neatlogs.com in docs, repeated in every versioned copy.
func TestARoleMailboxIsNotPersonalData(t *testing.T) {
	for _, line := range []string{
		`  email: support@crewai.com`,
		`- 📧 Contact: hello@neatlogs.com`,
		`"user.email=deploy@crewai.com",`,
		`sender = "noreply@acme-corp.io"`,
		`SECURITY_CONTACT = "security@acme-corp.io"`,
	} {
		if dataFired(t, "docs/page.mdx", line+"\n") {
			t.Errorf("DATA-001 reported a role mailbox as personal data: %s", line)
		}
	}
}

// The user:password@host part of a connection URL is not an e-mail address,
// though the rule's pattern (a separator, then local@domain) matches it.
func TestURLUserinfoIsNotAnEmailAddress(t *testing.T) {
	for _, line := range []string{
		`NILE_SERVICE_URL = "postgresql://nile:password@db.thenile.dev:5432/nile"`,
		`url = "mysql://root:p455w0rd@s2-host.com:3306/db"`,
	} {
		if dataFired(t, "docs/page.md", line+"\n") {
			t.Errorf("DATA-001 reported URL userinfo as an e-mail address: %s", line)
		}
	}
}

// A person's address is still personal data.
func TestAPersonalAddressIsStillReported(t *testing.T) {
	for _, line := range []string{
		`openalex_reader = OpenAlexReader(email="shauryr@gmail.com")`,
		`owner: "jane.doe@acme-corp.io"`,
		`"author_email": "supporter.jane@acme-corp.io"`, // a word that starts like a role is not one
	} {
		if !dataFired(t, "src/app.py", line+"\n") {
			t.Errorf("DATA-001 no longer reports a personal address: %s", line)
		}
	}
}
