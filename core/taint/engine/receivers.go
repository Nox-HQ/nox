package engine

import (
	"regexp"
	"strings"
)

// Python receiver bindings: a local that holds a DB-API cursor or connection
// stands for `cursor` or `connection` in a call chain, and one that holds an
// LDAP connection for `ldap_connection`.
//
// The catalog names Python's SQL sinks by receiver -- cursor.execute,
// connection.execute -- and chains are matched as written, so the sink matched
// only when the variable was literally named `cursor` or `connection`. What
// people write is `cur = con.cursor()`, `c = db.cursor()`,
// `with conn.cursor() as c:`. Every SQL case in the OWASP Benchmark for Python
// is written that way; nox reported none of them.
//
// The binding is read from how the value was made, not from its name: a local
// assigned from `<anything>.cursor(...)` is a cursor, one assigned from
// `<anything>.connect(...)` is a connection. Like import aliases, the resolved
// chain is ADDED beside the original (see applyImportAliases), so a call that
// matched before still matches and nothing can be lost. The binding is
// file-wide, as the import table is: a same-named local elsewhere in the file
// gains a redundant chain, not a removed one.
var (
	pyAssignFromCall = regexp.MustCompile(`^\s*([A-Za-z_]\w*)\s*=\s*[^=].*\.(cursor|connect)\s*\(`)
	pyWithAsCall     = regexp.MustCompile(`^\s*(?:async\s+)?with\s+.*\.(cursor|connect)\s*\([^)]*\)\s+as\s+([A-Za-z_]\w*)\s*:`)
)

var pyReceiverKind = map[string]string{"cursor": "cursor", "connect": "connection"}

// An LDAP connection is bound the same way, from what made it. ldap3's
// `Connection.search(base, filter)` is the injection sink, but `search` is
// the most generic method name there is -- `re.search`, a vector store's
// `index.search(query)` -- so the sink cannot be keyed on it. A local assigned
// from a call whose chain names LDAP (`ldap3.Connection(...)`,
// `ldap.initialize(...)`, a project's `helpers.ldap.get_connection()`), or
// from ldap3's Connection imported by name, stands for `ldap_connection`, and
// only `ldap_connection.search` is a sink.
var (
	pyAssignFromAnyCall = regexp.MustCompile(`^\s*([A-Za-z_]\w*)\s*=\s*([A-Za-z_][\w.]*)\s*\(`)
	pyWithAsAnyCall     = regexp.MustCompile(`^\s*(?:async\s+)?with\s+([A-Za-z_][\w.]*)\s*\(.*\)\s+as\s+([A-Za-z_]\w*)\s*:`)
)

// madeByLDAP reports whether a constructor or factory chain produces an LDAP
// connection: a segment naming LDAP, or a name imported from an LDAP module.
func madeByLDAP(chain string, imports map[string]string) bool {
	for _, seg := range strings.Split(chain, ".") {
		if strings.Contains(strings.ToLower(seg), "ldap") {
			return true
		}
	}
	head, _, _ := strings.Cut(chain, ".")
	return strings.Contains(strings.ToLower(imports[head]), "ldap")
}

// pythonReceiverBindings maps each local that holds a cursor or connection to
// the receiver name the catalog uses for it.
func pythonReceiverBindings(content []byte) map[string]string {
	out := map[string]string{}
	imports := pythonAliases(content)
	for _, line := range strings.Split(string(content), "\n") {
		if m := pyAssignFromCall.FindStringSubmatch(line); m != nil {
			out[m[1]] = pyReceiverKind[m[2]]
			continue
		}
		if m := pyWithAsCall.FindStringSubmatch(line); m != nil {
			out[m[2]] = pyReceiverKind[m[1]]
			continue
		}
		if m := pyAssignFromAnyCall.FindStringSubmatch(line); m != nil && madeByLDAP(m[2], imports) {
			out[m[1]] = "ldap_connection"
			continue
		}
		if m := pyWithAsAnyCall.FindStringSubmatch(line); m != nil && madeByLDAP(m[1], imports) {
			out[m[2]] = "ldap_connection"
		}
	}
	return out
}
