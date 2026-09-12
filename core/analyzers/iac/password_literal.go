package iac

import "strings"

// IAC-225 stopped being an Ansible rule when it was renamed to "Hardcoded
// password in a YAML configuration value": its subject is a YAML mapping key
// whose name ends in `password` and whose value is a literal, which is not an
// Ansible concept. The measurement that prompted the rename found real hits in
// Kubernetes Secrets and a Cassandra config. Its helpers follow it out of
// rules_ansible.go.

// nonSecretScalars are YAML scalars that answer "what password?" with
// something other than a password.
//
// `omit` is Ansible's explicit "leave this parameter out"; the booleans and
// nulls are how a task says a password is not set at all. Reporting any of them
// as a hardcoded credential is the false positive that the quoted-value
// requirement used to prevent by accident, and that a charset cannot prevent on
// purpose — they are made of exactly the characters a password is made of.
var nonSecretScalars = map[string]bool{
	"omit": true, "null": true, "none": true, "nil": true, "~": true,
	"true": true, "false": true, "yes": true, "no": true, "on": true, "off": true,
	"absent": true, "present": true, "undefined": true,
}

// passwordValueIsLiteral reports whether a `password:` match carries a literal
// value rather than a keyword.
//
// It receives the matched text only — `PASSWORD: root`, quotes included when
// the document wrote them — so it re-splits on the colon rather than being
// handed the value. That is the contract of rules.Rule.ValidateMatch: a pure
// function of the match, which is what keeps it from smuggling in line state.
func passwordValueIsLiteral(matchText string) bool {
	_, value, ok := strings.Cut(matchText, ":")
	if !ok {
		return false
	}
	value = strings.TrimSpace(value)
	value = strings.Trim(value, `"'`)
	if value == "" {
		return false
	}
	return !nonSecretScalars[strings.ToLower(value)]
}
