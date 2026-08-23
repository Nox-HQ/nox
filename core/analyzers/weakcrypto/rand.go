// Insecure randomness — CRYPTO-002.
//
// WHY THIS RULE EXISTS. `math/rand` is a deterministic PRNG. Its output is
// predictable from a handful of observed values, so a session token, password,
// nonce, salt or API key produced from it is guessable by anyone who can see a
// few earlier ones. That is CWE-338, and it is genuinely exploitable — this is
// not a hygiene rule. gosec has caught it as G404 for years; nox had no
// equivalent, which is a real gap for Go codebases that dropped gosec.
//
// WHY IT IS NOT "FLAG math/rand". This is the crux of the rule, and the reason
// it looks more complicated than a regex. `math/rand` is CORRECT — the right
// tool, not a tolerated one — for retry jitter, exponential-backoff spread,
// load-balancer and shard selection, sampling, shuffling, test fixtures and
// anything else where an adversary predicting the value costs nothing. Those
// call sites vastly outnumber the security-bearing ones in real code. A rule
// that flags all of them is noise, and noise is how a rule gets globally
// disabled, which leaves the codebase worse off than having no rule at all.
// CRYPTO-001's header says the same thing about MD5; the asymmetry is even
// sharper here, because the safe uses are the majority.
//
// HOW THE SECURITY CONTEXT IS DECIDED. Without go/types we cannot follow the
// value to a crypto sink, so the signal comes from the names around the call —
// what it is assigned to, what it is passed to, and the function it sits in.
// An identifier that splits into a word like `token`, `secret`, `key`, `nonce`,
// `salt`, `password`, `session`, `iv`, `apikey`, `credential`, `csrf`, `otp` or
// `auth` is the developer stating the value is security-bearing. A word like
// `jitter`, `backoff`, `delay`, `sleep`, `retry`, `sample`, `shuffle`, `pick`
// or `choose` is the developer stating the opposite, and it VETOES the finding
// even when a security word is also present — so `authRetryDelay` stays quiet.
// Benign beating security is deliberate: every ambiguous case resolves to
// silence.
//
// Four further discriminators exist because measurement demanded them, not by
// anticipation; each is documented at its declaration below:
//
//   - the enclosing function's name accuses only alongside a producer verb, so
//     `newPassword` fires and `handleAuth` does not (producerWords);
//   - a name that measures rather than holds — `maxTokens`, `keyLen` — does not
//     accuse (quantityWords);
//   - a `len(…)`-bounded draw is a choice of element, so a variable name cannot
//     accuse on it (isIndexDraw);
//   - a getter, or a string literal beside the call, can exonerate but never
//     accuse (lookupPrefixes, and the BasicLit branch of contextNames).
//
// MEASURED, not assumed. On the Go module cache, 851 non-test files importing
// math/rand yield 4 findings — before these four discriminators it was 10, and
// the 6 removed were a cache key, two shard selections, an index draw and a
// duplicate. On a 23-repository Go fleet (7,720 files) it yields 0, while gosec
// reports 9 G404 hits there, every one of them a jitter, chaos-test or
// simulation call already carrying a `//nolint:gosec` explaining why it is
// fine. That the rule is silent on all 9 is the point of it.
//
// KNOWN FALSE NEGATIVES, stated plainly. A generator with no descriptive names
// (`b := make([]byte, 16); rand.Read(b)` in `func gen()`) is not caught. Nor is
// a value laundered through a neutrally-named helper in another file, nor an
// interface-typed RNG, nor a dot-import of math/rand. This rule catches the
// obvious naming cases and nothing else. That is the intended trade: a rule
// that finds most of these and never cries wolf is worth more than one that
// finds nearly all of them and gets suppressed org-wide in its first week.
// The remediation text says so too, because a finding's ABSENCE must not be
// read as proof that a file generates its secrets safely.

package weakcrypto

import (
	"go/ast"
	"go/token"
	"strings"
	"unicode"

	"github.com/nox-hq/nox/core/source"

	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/rules"
)

// randRuleID is the insecure-randomness rule.
const randRuleID = "CRYPTO-002"

// mathRandPaths are the import paths that bind a predictable PRNG. Both the v1
// and v2 packages are deterministic; v2 changed the algorithm and the API, not
// the guarantee. `crypto/rand` is deliberately absent — it is the CORRECT API,
// and because it is also imported as the identifier `rand`, resolving the
// import path (rather than matching the text `rand.Read`) is what keeps this
// rule from flagging the fix it recommends.
var mathRandPaths = []string{"math/rand", "math/rand/v2"}

// securityWords mark a value whose predictability is exploitable. Matching is
// on WORDS extracted from an identifier, never substrings: `monkey` and
// `keyboard` do not contain the word `key`, and treating them as if they did is
// exactly the over-flagging this rule is built to avoid.
//
// `seed` is deliberately NOT here, though a seed for key derivation would
// qualify. In Go the word overwhelmingly names a PRNG's own seed — `seed :=
// time.Now().UnixNano()`, `rand.New(rand.NewSource(seed))` — so including it
// would fire on the benign construction of the very generator this rule tracks.
// The rare key-derivation seed is an accepted false negative.
var securityWords = map[string]bool{
	"token": true, "secret": true, "key": true, "nonce": true,
	"salt": true, "password": true, "passwd": true, "pwd": true,
	"session": true, "iv": true, "apikey": true, "credential": true,
	"csrf": true, "xsrf": true, "otp": true, "auth": true,
	"jwt": true, "hmac": true,
}

// producerWords mark a function whose JOB is to produce a value. The enclosing
// function's name is the weakest of the context signals — a random draw can sit
// anywhere inside a long `handleAuth`, and flagging every one of those is how
// this rule would earn its suppression. Requiring a producer verb alongside the
// security noun restricts the signal to functions that generate the secret
// (`generateToken`, `newPassword`, `randomKey`, `newIV`) rather than functions
// that merely operate near one. Measured on the fixture set, this is what
// separates `newPassword` (fires) from `handleAuth` (silent).
var producerWords = map[string]bool{
	"new": true, "generate": true, "gen": true, "create": true,
	"make": true, "random": true, "rand": true, "build": true,
	"issue": true, "mint": true, "derive": true, "fresh": true,
}

// quantityWords mark a name that measures or locates something rather than
// holding it: `maxTokens`, `keyLen`, `sessionCount`, `tokenIndex`. The value is
// a size or a position, not the secret, so such a name does not supply the
// security signal — though it does not veto one coming from elsewhere, so a
// `keyLen` inside `generateKey` is still reported.
var quantityWords = map[string]bool{
	"len": true, "length": true, "size": true, "count": true,
	"num": true, "index": true, "idx": true, "offset": true,
	"max": true, "min": true, "limit": true, "cap": true,
	"capacity": true, "total": true, "position": true, "pos": true,
}

// lookupPrefixes name a call that RETRIEVES rather than stores. An enclosing
// call is normally good evidence of what a value is for — `SetSessionToken(…)`
// is damning — but a getter inverts it: in `GetByKey(strconv.Itoa(rand.Int()))`
// the random value picks an entry, it does not become a secret. Measured on the
// Go module cache, this single distinction removed a false positive in
// `go-redis`'s ring shard selection.
var lookupPrefixes = map[string]bool{
	"get": true, "find": true, "lookup": true, "load": true,
	"fetch": true, "select": true, "index": true, "has": true,
	"contains": true, "exists": true, "at": true,
}

// benignWords mark a use where predictability is harmless — and where
// `math/rand` is the right choice, not a lapse. A benign word anywhere in the
// context vetoes the finding, including when a security word is also present.
var benignWords = map[string]bool{
	"jitter": true, "jittered": true, "backoff": true, "delay": true,
	"sleep": true, "wait": true, "timeout": true, "retry": true,
	"retries": true, "poll": true, "sample": true, "sampling": true,
	"shuffle": true, "pick": true, "choose": true, "choice": true,
	"cache": true, "test": true, "testing": true, "fake": true,
	"mock": true, "dummy": true, "stub": true, "fixture": true,
	"example": true, "demo": true, "bench": true, "benchmark": true,
}

// randRule describes CRYPTO-002 for the rule catalogue.
//
// SEVERITY: high, at medium confidence. The alternative — medium — was
// rejected because it makes the rule decorative in the setup that motivated it:
// CI gates commonly fail only on net-new critical/high, so a medium rule ships
// as a report-only line item that nobody actions. The impact when this fires is
// not medium either: a predictable session token or password-reset token is
// account takeover, reachable with arithmetic and no privileged position.
//
// Gating carries an obligation the rest of this file discharges: the rule must
// stay quiet unless the surrounding code says the value is security-bearing,
// and every ambiguous case must resolve to silence. Confidence is medium rather
// than high because the security context is asserted by naming, not proven by
// type analysis.
func randRule() *rules.Rule {
	return &rules.Rule{
		ID:          randRuleID,
		Version:     "1.0",
		Description: "Predictable randomness (math/rand) used for a security-bearing value",
		Severity:    findings.SeverityHigh,
		Confidence:  findings.ConfidenceMedium,
		Tags:        []string{"crypto", "weak-random", "owasp-a02"},
		Remediation: "`math/rand` is a deterministic PRNG: its output is predictable from a small number of observed values, so a token, key, nonce, salt, password or session identifier derived from it is guessable. " +
			"Use `crypto/rand` instead — `crypto/rand.Read` for raw bytes, `crypto/rand.Int` for a bounded integer, or `crypto/rand.Text` (Go 1.24+) for a random string — and encode the bytes with `encoding/hex` or `encoding/base64` rather than deriving characters with a modulo. " +
			"This rule fires only where the surrounding names say the value is security-bearing, so `math/rand` for jitter, backoff, sampling, shuffling or load balancing is not reported and needs no change; conversely, a security-bearing generator whose variables are named neutrally will NOT be caught, so this finding's absence is not evidence a file is clean. " +
			"If the value here genuinely is not security-bearing, suppress it with a nox:ignore comment recording that reason.",
		References: []string{
			"https://cwe.mitre.org/data/definitions/338.html",
			"https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
			"https://pkg.go.dev/crypto/rand",
		},
		Metadata: map[string]string{"cwe": "CWE-338"},
	}
}

// scanInsecureRandom reports math/rand values that flow into a security-bearing
// name in one Go source file.
//
// The file is parsed rather than pattern-matched. A regex cannot tell
// `crypto/rand.Read` from `math/rand.Read` — both are written `rand.Read` — and
// flagging the recommended fix would discredit the rule immediately. Parsing
// also removes comments and string literals from consideration for free.
func scanInsecureRandom(fs *findings.FindingSet, art discovery.Artifact, content []byte) {
	// The path gives the taint/position metadata a real filename; a non-compiling
	// file still yields the recovered partial AST.
	file, fset := source.ParseGoFile(art.Path, content)
	if file == nil {
		return
	}

	pkgNames := source.ImportAliases(file, mathRandPaths...)
	if len(pkgNames) == 0 {
		return
	}
	// Locals holding a *rand.Rand from `rand.New(...)`, so the receiver call
	// style (`rng.Intn(n)`) is covered as well as the package call style.
	// File-scoped and name-only: shadowing in an inner block is not modelled,
	// which can only cost a finding, never invent one.
	rngVars := seededRandVars(file, pkgNames)

	reported := map[int]bool{}
	stack := make([]ast.Node, 0, 32)

	ast.Inspect(file, func(n ast.Node) bool {
		// ast.Inspect pairs every non-nil node with a later nil call, so the
		// stack stays balanced; the guard is there because a panic inside an
		// analyzer would take the whole scan down.
		if n == nil {
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			return true
		}
		defer func() { stack = append(stack, n) }()

		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		fn, isWeak := weakRandCall(call, pkgNames, rngVars)
		if !isWeak {
			return true
		}
		line := fset.Position(call.Pos()).Line
		if reported[line] {
			return true
		}

		ctx := contextNames(call, stack)
		hit, vetoed := classify(ctx, isIndexDraw(call))
		if vetoed || hit == "" {
			return true
		}

		reported[line] = true
		fs.Add(findings.Finding{
			RuleID:     randRuleID,
			Severity:   findings.SeverityHigh,
			Confidence: findings.ConfidenceMedium,
			Message: "Predictable randomness: math/rand." + fn +
				" produces a value named for a security use (" + hit + "); use crypto/rand",
			Location: findings.Location{
				FilePath:  art.Path,
				StartLine: line,
				EndLine:   line,
			},
			Metadata: map[string]string{
				"cwe":      "CWE-338",
				"function": fn,
				"context":  hit,
			},
		})
		return true
	})
}

// mathRandImportNames returns the identifiers bound to a math/rand package in
// this file — the default `rand`, or whatever alias the import gives it. A dot
// import is not handled: it makes the call indistinguishable from a local
// function without type information, and it is vanishingly rare.
// seededRandVars collects the names assigned a `*rand.Rand` from `rand.New(…)`,
// so calls on that receiver are recognised. Both `r := rand.New(…)` and
// `s.rng = rand.New(…)` are handled; only the final identifier is kept.
func seededRandVars(file *ast.File, pkgNames map[string]bool) map[string]bool {
	vars := map[string]bool{}
	record := func(lhs []ast.Expr, rhs []ast.Expr) {
		for i, r := range rhs {
			call, ok := r.(*ast.CallExpr)
			if !ok || i >= len(lhs) {
				continue
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "New" {
				continue
			}
			if id, ok := sel.X.(*ast.Ident); !ok || !pkgNames[id.Name] {
				continue
			}
			if name := trailingName(lhs[i]); name != "" {
				vars[name] = true
			}
		}
	}
	ast.Inspect(file, func(n ast.Node) bool {
		switch s := n.(type) {
		case *ast.AssignStmt:
			record(s.Lhs, s.Rhs)
		case *ast.ValueSpec:
			lhs := make([]ast.Expr, 0, len(s.Names))
			for _, nm := range s.Names {
				lhs = append(lhs, nm)
			}
			record(lhs, s.Values)
		}
		return true
	})
	return vars
}

// weakRandCall reports whether a call draws from a math/rand generator, and
// returns the function name for the message.
//
// Constructors and seeding (`New`, `NewSource`, `NewPCG`, `Seed`) are excluded:
// they configure a generator rather than producing a value, so flagging them
// would report the setup line instead of the use — and `rand.New` appears in
// plenty of code whose draws are all benign.
func weakRandCall(call *ast.CallExpr, pkgNames, rngVars map[string]bool) (string, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	fn := sel.Sel.Name
	if fn == "Seed" || strings.HasPrefix(fn, "New") {
		return "", false
	}
	switch x := sel.X.(type) {
	case *ast.Ident:
		if pkgNames[x.Name] || rngVars[x.Name] {
			return fn, true
		}
	case *ast.SelectorExpr:
		// A generator held in a field: `s.rng.Intn(n)`.
		if rngVars[x.Sel.Name] {
			return fn, true
		}
	}
	return "", false
}

// ctxName is one identifier describing a random value's use, tagged with the
// role it plays. Every context name can VETO; what it takes to ACCUSE depends
// on the role.
type ctxName struct {
	name string
	role role
}

type role int

const (
	// roleValue: a name the value itself takes on — an assignment target, a
	// struct field, a buffer passed to Read, the function it is handed to.
	roleValue role = iota
	// roleFunc: the enclosing function's name. Accuses only when it also
	// carries a producer verb (see producerWords).
	roleFunc
	// roleVetoOnly: a name that describes the surroundings without saying the
	// value is security-bearing — a getter, or a string literal sitting beside
	// the call. It can exonerate but never accuse.
	roleVetoOnly
)

// contextNames gathers the identifiers that describe what a random value is
// FOR: what it is assigned to, the struct field it initialises, the functions
// it is passed to, and the function it sits in.
//
// `Read` is special-cased: its output is the buffer argument, so `rand.Read(
// token)` takes its meaning from the argument rather than from an assignment.
func contextNames(call *ast.CallExpr, stack []ast.Node) []ctxName {
	var names []ctxName
	add := func(n string, r role) {
		if n != "" {
			names = append(names, ctxName{name: n, role: r})
		}
	}

	if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Read" {
		for _, arg := range call.Args {
			add(trailingName(arg), roleValue)
		}
	}

	for i := len(stack) - 1; i >= 0; i-- {
		switch node := stack[i].(type) {
		case *ast.AssignStmt:
			for _, lhs := range node.Lhs {
				add(trailingName(lhs), roleValue)
			}
		case *ast.ValueSpec:
			for _, nm := range node.Names {
				add(nm.Name, roleValue)
			}
		case *ast.KeyValueExpr:
			add(trailingName(node.Key), roleValue)
		case *ast.CallExpr:
			// An enclosing call names the destination of the value:
			// `time.Sleep(…)` is benign, `setSessionKey(…)` is not — unless it
			// is a lookup, where the value selects rather than becomes.
			fname := trailingName(node.Fun)
			r := roleValue
			if isLookup(fname) {
				r = roleVetoOnly
			}
			add(fname, r)
			// A string literal in the same call describes the value as surely as
			// an identifier does: `fmt.Sprintf("cache_key_%d", rand.Intn(50))`
			// says "cache" even though no variable does. Veto-only, because a
			// literal is far too weak to accuse on.
			for _, arg := range node.Args {
				if lit, ok := arg.(*ast.BasicLit); ok && lit.Kind == token.STRING {
					add(strings.Trim(lit.Value, "`\""), roleVetoOnly)
				}
			}
		case *ast.FuncDecl:
			// Accuses only for a generator; see producerWords.
			add(node.Name.Name, roleFunc)
		}
	}
	return names
}

// isProducer reports whether a function name claims to MAKE something.
func isProducer(name string) bool {
	for _, w := range identWords(name) {
		if producerWords[w] {
			return true
		}
	}
	return false
}

// isLookup reports whether a call name retrieves something.
func isLookup(name string) bool {
	w := identWords(name)
	return len(w) > 0 && lookupPrefixes[w[0]]
}

// isIndexDraw reports whether the draw is bounded by `len(…)` — the shape of
// picking an element, not of generating a secret. `i := rand.Intn(len(hosts))`
// is a choice however the variable is named, so a name like `keyInd` must not
// accuse on its own.
//
// It only disqualifies name-derived evidence: a len-bounded draw inside
// `newPassword` is still reported, because `charset[rand.Intn(len(charset))]`
// is exactly how a weak password generator is written.
func isIndexDraw(call *ast.CallExpr) bool {
	found := false
	for _, arg := range call.Args {
		ast.Inspect(arg, func(n ast.Node) bool {
			if c, ok := n.(*ast.CallExpr); ok {
				if id, ok := c.Fun.(*ast.Ident); ok && id.Name == "len" {
					found = true
				}
			}
			return !found
		})
	}
	return found
}

// trailingName returns the last identifier of a simple expression: `x` for `x`,
// `Token` for `s.Token`, `buf` for `buf[:]` and `keys` for `keys[i]`. Anything
// more complex yields "" — an unnamed destination carries no signal either way.
func trailingName(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		if v.Name == "_" {
			return ""
		}
		return v.Name
	case *ast.SelectorExpr:
		return v.Sel.Name
	case *ast.IndexExpr:
		return trailingName(v.X)
	case *ast.SliceExpr:
		return trailingName(v.X)
	case *ast.StarExpr:
		return trailingName(v.X)
	case *ast.UnaryExpr:
		return trailingName(v.X)
	case *ast.ParenExpr:
		return trailingName(v.X)
	}
	return ""
}

// classify splits every context identifier into words and reports the
// security word that justifies a finding, plus whether a benign word vetoes it.
//
// The veto is evaluated over ALL names, not just the closest one, and wins
// outright. `sessionRetryDelay` and a jitter computed inside `refreshAuthToken`
// both stay silent. Losing those to a false negative is the cheaper error.
func classify(names []ctxName, indexDraw bool) (hit string, vetoed bool) {
	for _, c := range names {
		words := identWords(c.name)
		quantity := false
		for _, w := range words {
			if benignWords[w] || benignWords[singular(w)] {
				return "", true
			}
			if quantityWords[w] || quantityWords[singular(w)] {
				quantity = true
			}
		}
		accuses := c.role == roleValue && !indexDraw ||
			c.role == roleFunc && isProducer(c.name)
		if hit != "" || !accuses || quantity {
			continue
		}
		for _, w := range words {
			if securityWords[w] || securityWords[singular(w)] {
				hit = c.name
				break
			}
		}
	}
	return hit, false
}

// singular strips a trailing plural "s" so `keys`, `tokens` and `credentials`
// match their singular entries. Short words are left alone.
func singular(w string) string {
	if len(w) > 3 && strings.HasSuffix(w, "s") {
		return strings.TrimSuffix(w, "s")
	}
	return w
}

// identWords splits an identifier into lowercase words on camelCase, acronym,
// underscore and digit boundaries: `sessionToken` and `session_token` and
// `APIKey` and `csrfToken2` all yield the words a human reads in them.
//
// Word-level matching, rather than substring matching, is what keeps `monkey`,
// `keyboard` and `passthrough` out of the security set.
func identWords(id string) []string {
	var out []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			out = append(out, strings.ToLower(string(cur)))
			cur = nil
		}
	}
	rs := []rune(id)
	for i, r := range rs {
		switch {
		case r == '_' || r == '-' || r == '.' || unicode.IsDigit(r):
			flush()
		case unicode.IsUpper(r):
			// Start a new word at a lower→upper transition (`apiKey`), or at the
			// last capital of an acronym run followed by lowercase (`APIKey`).
			if i > 0 && (!unicode.IsUpper(rs[i-1]) ||
				(i+1 < len(rs) && unicode.IsLower(rs[i+1]))) {
				flush()
			}
			cur = append(cur, r)
		default:
			cur = append(cur, r)
		}
	}
	flush()
	return out
}
