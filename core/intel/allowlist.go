// Package intel derives and transmits the observations this installation
// contributes to a NOX Intelligence service.
//
// Minimization happens here, in the binary the operator runs, and nowhere else.
// If the service performed the redaction, the raw data would already have left
// the environment — so the privacy contract, *share security facts, never
// customer artifacts*, is only credible if the narrowing is done client-side
// and is auditable.
//
// The narrowing is an allowlist, not a denylist. A denylist of patterns fails
// the moment a new field is added: the field is simply not on the list of
// things to strip, so it ships. An allowlist fails closed, because a field
// nobody deliberately permitted is a field that does not exist in Observation.
package intel

import (
	"fmt"
	"io"
	"strings"
)

// AllowedField is one field an observation may carry, and why.
type AllowedField struct {
	Name    string
	Purpose string
}

// Allowlist is the complete set of fields that may leave this installation.
//
// It is exported and printable so that "what would you send?" is answerable
// without reading the source. Adding a field here is the only way to widen what
// is transmitted, and the round-trip test asserts this list and the Observation
// struct agree — a field added to one and not the other fails the build's tests
// rather than silently shipping or silently vanishing.
func Allowlist() []AllowedField {
	return []AllowedField{
		{"fingerprint", "hash of the security facts below; the clustering key"},
		{"ecosystem", "package ecosystem, e.g. npm, go, pypi"},
		{"package", "package name as published by its registry"},
		{"version_range", "affected version range, normalized"},
		{"weakness", "weakness class, e.g. a CWE identifier"},
		{"rule_id", "the nox rule that produced the finding"},
		{"reporter_id", "opaque per-installation id, for counting distinct reporters"},
		{"observed_at", "when this installation saw it"},
		{"tool_version", "the nox build that produced it, so a claim is traceable"},
	}
}

// NeverShared names the categories that do not leave the environment in any
// contribution mode. It exists to be printed alongside the allowlist: a list of
// what is shared reads very differently next to the list of what never is.
func NeverShared() []string {
	return []string{
		"source code and file contents",
		"file paths, repository names, and directory structure",
		"secrets, credentials, and tokens",
		"prompts, model responses, and AI application data",
		"customer data of any kind",
		"raw application traffic",
		"hostnames, IP addresses, and any identifier of who is reporting",
	}
}

// PrintAllowlist writes the allowlist and the never-shared categories in a form
// an operator or an auditor can read.
func PrintAllowlist(w io.Writer) error {
	var b strings.Builder

	b.WriteString("Fields an observation may carry:\n\n")
	for _, f := range Allowlist() {
		fmt.Fprintf(&b, "  %-14s %s\n", f.Name, f.Purpose)
	}

	b.WriteString("\nNever transmitted, in any contribution mode:\n\n")
	for _, s := range NeverShared() {
		b.WriteString("  - " + s + "\n")
	}

	b.WriteString("\nMinimization happens in this binary, before anything leaves.\n" +
		"Contribution is off unless scan.intelligence.contribute is set, and is\n" +
		"a separate decision from querying an intelligence endpoint.\n")

	_, err := io.WriteString(w, b.String())
	return err
}
