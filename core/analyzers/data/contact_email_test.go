package data

import "testing"

// DATA-001 reports PII hard-coded in source, and advises "remove or externalize
// PII data". For an address a project publishes as its own contact point, that
// advice is wrong and the finding describes no data-handling failure.
//
// Measured on the pinned corpus: 969 findings over 177 distinct addresses, 716
// of them `support@crewai.com`. 42.9% sat inside a `mailto:` URI and 23.6% in a
// package manifest's author field; the rest were OpenAPI `contact:` blocks and
// documentation support sections, including translated copies of one page.

func dataFired(t *testing.T, path, body string) bool {
	t.Helper()
	a := NewAnalyzer()
	got, err := a.ScanFile(path, []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range got {
		if f.RuleID == "DATA-001" {
			return true
		}
	}
	return false
}

// TestAMailtoAddressIsPublished — it exists so a reader can write to it.
func TestAMailtoAddressIsPublished(t *testing.T) {
	for _, line := range []string{
		`<a href="mailto:support@crewai.com">Support</a>`,
		`- **Support**: Contact [support@crewai.com](mailto:support@crewai.com)`,
		`MAILTO:Support@CrewAI.com`,
	} {
		if dataFired(t, "docs/introduction.mdx", line+"\n") {
			t.Errorf("DATA-001 reported a mailto: address as PII: %s", line)
		}
	}
}

// TestAManifestAuthorAddressIsPublished — it ships to the registry.
func TestAManifestAuthorAddressIsPublished(t *testing.T) {
	for path, line := range map[string]string{
		"pyproject.toml": `authors = [{name = "CrewAI", email = "support@crewai.com"}]`,
		"package.json":   `"author": {"email": "hello@neatlogs.com"}`,
		"Cargo.toml":     `maintainer = "dev@example.org"`,
	} {
		if dataFired(t, path, line+"\n") {
			t.Errorf("DATA-001 reported a %s author address as PII: %s", path, line)
		}
	}
}

// TestARealAddressInCodeIsStillReported is the recall half: the rule exists for
// a personal address sitting somewhere it was not meant to be published.
func TestARealAddressInCodeIsStillReported(t *testing.T) {
	for path, line := range map[string]string{
		"app/handlers.py": `admin_notify = "jane.doe@internalcorp.com"`,
		"config/prod.yml": `alert_recipient: "oncall.engineer@internalcorp.com"`,
	} {
		if !dataFired(t, path, line+"\n") {
			t.Errorf("DATA-001 stopped reporting an address in %s: %s", path, line)
		}
	}
}

// TestANonContactFieldInAManifestStillReports. The manifest exclusion is scoped
// to author/maintainer/contact fields, not to the whole file.
func TestANonContactFieldInAManifestStillReports(t *testing.T) {
	if !dataFired(t, "pyproject.toml", `default_test_user = "someone.real@internalcorp.com"`+"\n") {
		t.Error("the manifest exclusion swallowed an address that is not a contact field; " +
			"it is scoped to author/maintainer/contact, not to the file")
	}
}
