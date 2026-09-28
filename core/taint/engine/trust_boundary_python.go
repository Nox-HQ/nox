package engine

import (
	"regexp"
	"strings"

	"github.com/nox-hq/nox/core/lexctx"
)

// Trust-boundary violation (CWE-501) in Python: an untrusted value stored in
// the server-side session.
//
// A session is where an application keeps what it has established -- who the
// user is, what they are allowed to do. Writing request data into it, as a key
// or a value, lets later code read attacker-chosen data as if the application
// had put it there: `session['user'] = request.form['user']` before the
// password is checked is the textbook case.
//
// It is also common and often harmless (`session['lang'] = request.args['lang']`),
// so the sink is OPT-IN (catalog `opt_in`, enabled by naming TAINT-011 in
// scan.rules.enable) and reported at low severity. Measured before deciding: 5
// of 53 Flask files from GitHub search wrote request data straight into the
// session, a mix of preferences and pre-authentication identity.
//
// A subscript store is an assignment, not a call, so like XXE the sink is a
// synthetic chain added to the statement: `session[...] = ...`,
// `flask.session[...]`, Django's `request.session[...]`. The engine then asks
// the usual question -- is anything the statement reads tainted? -- which
// covers a tainted key and a tainted value alike.

const sessionStoreSinkCall = "trust_boundary.session_store"

var pySessionStore = regexp.MustCompile(`^\s*(?:[A-Za-z_]\w*\.)*session\s*\[[^\]]*\]\s*=[^=]`)

// applySessionStores marks each statement that stores into a session.
func applySessionStores(drafts []unitDraft, content []byte) {
	if !strings.Contains(string(content), "session") {
		return
	}
	lines := strings.Split(string(lexctx.MaskNonCode(lexctx.LangPython, content)), "\n")
	for i := range drafts {
		for j := range drafts[i].stmts {
			st := &drafts[i].stmts[j]
			if st.line < 1 || st.line > len(lines) || !pySessionStore.MatchString(lines[st.line-1]) {
				continue
			}
			st.calls = append(st.calls, sessionStoreSinkCall)
		}
	}
}
