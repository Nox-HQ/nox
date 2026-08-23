// Package hardening detects transport-security misconfiguration in Go source:
// TLS settings that are syntactically fine and semantically dangerous.
//
// WHY THIS EXISTS. Nothing in core modelled `tls.Config`. Certificate
// validation could be switched off anywhere in a Go codebase and no nox rule
// would say a word — measured against gosec's G402 on a 38-repo Go fleet where
// gosec had just been removed from the shared golangci config, leaving nox as
// the only code-level security tool. That is the highest-severity coverage gap
// found, so it gets a rule.
//
// WHY IT IS NOT A TAINT RULE. There is no source to track. `InsecureSkipVerify:
// true` is dangerous on its own, independent of where any value came from — the
// same reason weakcrypto is its own analyzer rather than a taint sink.
//
// WHY AN AST AND NOT A REGEX. This is the one detection where a regex is
// actively misleading. `InsecureSkipVerify:\s*true` also matches the string
// inside a comment, and — worse — cannot distinguish `true` from a variable, so
// the only regex that "handles" `InsecureSkipVerify: skipVerify` is one that
// pretends a variable is a literal. nox is written in Go, so go/parser is free,
// precise, deterministic and adds no dependency; the taint engine already
// depends on it for exactly this reason (see docs/design/go-taint.md). The AST
// answers "is this a keyed field of a composite literal whose value is the
// identifier true" exactly, with no heuristics.
//
// SCOPE, deliberately narrow — the weakcrypto rule for the same reason:
// over-flagging is how a rule gets globally suppressed, which costs more than
// the rule is worth. Only literal `true` and literal below-1.2 version
// constants are reported. See the KNOWN LIMITS block on Analyzer for what this
// deliberately does not see.
package hardening

import (
	"bytes"
	"context"
	"go/ast"
	"go/token"
	"os"
	"path/filepath"
	"strings"

	"github.com/nox-hq/nox/core/source"

	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/rules"
)

// Rule IDs emitted by this analyzer. HARDEN-* is a new namespace: these are
// not broken primitives (CRYPTO-*), not infrastructure config (IAC-*) and not
// a data flow (TAINT-*) — they are dangerous transport-security options in
// application code. Neither ID collides with an existing rule.
const (
	// ruleInsecureSkipVerify: certificate validation switched off.
	ruleInsecureSkipVerify = "HARDEN-001"
	// ruleWeakTLSVersion: negotiated floor below TLS 1.2.
	ruleWeakTLSVersion = "HARDEN-002"
)

// Analyzer reports TLS misconfiguration in Go source.
//
// KNOWN LIMITS — stated here rather than discovered by a user:
//
//  1. VARIABLE VALUES ARE NOT RESOLVED. `InsecureSkipVerify: skipVerify` is not
//     reported. This analyzer walks the AST only; it does not run go/types or
//     constant propagation, so it cannot tell whether `skipVerify` is a
//     constant true, a --insecure flag that defaults to false, or a value that
//     is only ever true in a dev branch. Reporting it anyway would fire on the
//     config-driven pattern that most real codebases use, at the cost of the
//     rule being suppressed wholesale. This is a real blind spot, and the
//     dishonest alternative — a regex that "matches" the variable form without
//     knowing its value — is worse than the gap.
//
//  2. TEST FILES ARE SKIPPED. gosec flags `_test.go`; this does not. Tests
//     legitimately dial httptest TLS servers with self-signed certificates, and
//     `InsecureSkipVerify: true` is the documented way to do that. The rule is
//     High severity precisely so a CI gate can fail on it, which means every
//     such test would either block a legitimate PR or teach the team to
//     blanket-suppress HARDEN-001 — and a suppressed rule protects nothing. The
//     accepted cost: production behaviour that lives in a _test.go file is not
//     covered.
//
//  3. NO CROSS-FILE OR CROSS-PACKAGE VIEW. A helper that returns a
//     misconfigured *tls.Config is reported where the literal is written, not
//     where it is used.
//
//  4. GO ONLY. The equivalent in other languages (Python `verify=False`, Node
//     `rejectUnauthorized: false`) is a separate detection with separate
//     precision problems, and is not in this rule.
type Analyzer struct{}

// NewAnalyzer constructs the hardening analyzer.
func NewAnalyzer() *Analyzer { return &Analyzer{} }

// Rules returns the rules this analyzer can emit, for the rule catalogue.
func (a *Analyzer) Rules() *rules.RuleSet {
	rs := rules.NewRuleSet()
	rs.Add(&rules.Rule{
		ID:      ruleInsecureSkipVerify,
		Version: "1.0",
		Description: "TLS certificate verification disabled " +
			"(InsecureSkipVerify: true)",
		// High, not Medium. Disabling certificate verification removes
		// authentication from the connection entirely: any party that can
		// answer the DNS name or sit on the path can present any certificate
		// and read and rewrite the traffic. TLS without verification provides
		// no more security than plaintext against an active attacker, so it
		// belongs on the same line as a hardcoded credential — and, concretely,
		// gates that fail on net-new critical/high are the ones that stop it
		// reaching production. A Medium finding here would be decorative.
		Severity: findings.SeverityHigh,
		// High: the AST proves the field is set to the literal true. There is
		// no interpretation left — unlike CRYPTO-001, where the call site is
		// unambiguous but its purpose is not.
		Confidence: findings.ConfidenceHigh,
		Tags:       []string{"tls", "transport-security", "owasp-a02", "gosec-g402"},
		Remediation: "This disables TLS certificate verification, so the connection is authenticated against nobody: " +
			"any host that can answer for the address — an on-path attacker, a hijacked DNS record, a malicious proxy — " +
			"can present a self-signed certificate and read and modify everything sent over it. " +
			"Remove the field and let the platform trust store validate the peer. " +
			"If the peer uses a private or self-signed CA, do not skip verification — pin the CA instead by setting RootCAs to an x509.CertPool containing it, " +
			"and set ServerName when the certificate does not match the dial address. " +
			"If this is a deliberate, scoped exception (a local development target, a health probe against a host with no usable certificate), " +
			"suppress it with a nox:ignore comment recording that reason so the decision is reviewable.",
		References: []string{
			"https://cwe.mitre.org/data/definitions/295.html",
			"https://pkg.go.dev/crypto/tls#Config",
			"https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
		},
		Metadata: map[string]string{"cwe": "CWE-295", "gosec": "G402"},
	})
	rs.Add(&rules.Rule{
		ID:          ruleWeakTLSVersion,
		Version:     "1.0",
		Description: "TLS minimum version set below TLS 1.2",
		// Medium, not High, and the difference from HARDEN-001 is deliberate.
		// A TLS 1.0/1.1 floor is a real weakness — RFC 8996 deprecates both,
		// PCI DSS forbids them, and they carry cipher suites broken by BEAST
		// and by RC4 and 3DES weaknesses — but the peer is still
		// authenticated, and exploiting it requires an active on-path
		// attacker rather than merely a certificate. It is also, unlike
		// HARDEN-001, sometimes a defensible decision: a server that must
		// still serve identified legacy clients. Rating it High would put
		// "negotiates an old protocol" on the same gate line as "does not
		// check who it is talking to", which devalues the High tier and is how
		// severity inflation starts. Medium reports it without blocking.
		Severity: findings.SeverityMedium,
		// High: the value is a literal constant naming the version.
		Confidence: findings.ConfidenceHigh,
		Tags:       []string{"tls", "transport-security", "owasp-a02", "gosec-g402"},
		Remediation: "This pins the TLS floor below 1.2. TLS 1.0 and 1.1 are deprecated by RFC 8996 and disallowed by PCI DSS; " +
			"they permit cipher suites with known weaknesses (RC4, 3DES) and are vulnerable to downgrade and record-protocol attacks that TLS 1.2 and 1.3 are not. " +
			"Set MinVersion to tls.VersionTLS12, or tls.VersionTLS13 where every peer supports it. " +
			"Note that omitting MinVersion entirely is not equivalent to setting it high: it takes the Go default, which has changed between releases. Set it explicitly. " +
			"If a specific legacy peer genuinely requires an older protocol, keep the exception on the one client config that talks to it — not on a shared default — and record the reason in a nox:ignore comment.",
		References: []string{
			"https://cwe.mitre.org/data/definitions/327.html",
			"https://datatracker.ietf.org/doc/html/rfc8996",
			"https://pkg.go.dev/crypto/tls#Config",
		},
		Metadata: map[string]string{"cwe": "CWE-327", "gosec": "G402"},
	})
	return rs
}

// triggers are the identifiers that any finding requires literally in the
// source. Files containing neither are skipped without parsing — the AST is
// only worth its cost on the small fraction of files that mention TLS options
// at all.
var triggers = [][]byte{
	[]byte("InsecureSkipVerify"),
	[]byte("MinVersion"),
}

// ScanArtifacts reports TLS misconfiguration across discovered Go sources.
func (a *Analyzer) ScanArtifacts(ctx context.Context, artifacts []discovery.Artifact) (*findings.FindingSet, error) {
	fs := findings.NewFindingSet()

	for _, art := range artifacts {
		if err := ctx.Err(); err != nil {
			return fs, err
		}
		if !strings.EqualFold(filepath.Ext(art.Path), ".go") {
			continue
		}
		// See KNOWN LIMITS (2) on Analyzer for why test code is out of scope.
		if source.IsTestPath(art.Path) {
			continue
		}
		content, err := os.ReadFile(art.AbsPath)
		if err != nil {
			// Unreadable file is not a finding; discovery already surfaced it.
			continue
		}
		if !hasTrigger(content) {
			continue
		}
		for _, f := range scanGoSource(art.Path, content) {
			fs.Add(f)
		}
	}
	return fs, nil
}

// hasTrigger reports whether the source mentions any option this analyzer can
// report on.
func hasTrigger(content []byte) bool {
	for _, t := range triggers {
		if bytes.Contains(content, t) {
			return true
		}
	}
	return false
}

// scanGoSource parses one Go file and returns its findings.
func scanGoSource(path string, content []byte) []findings.Finding {
	file, fset := source.ParseGoFile(path, content)
	if file == nil {
		return nil
	}

	s := &scanner{
		path:    path,
		fset:    fset,
		tlsPkgs: source.ImportAliases(file, "crypto/tls"),
		elided:  map[ast.Node]bool{},
	}
	ast.Inspect(file, s.visit)
	return s.out
}

// scanner accumulates findings for one file.
type scanner struct {
	path string
	fset *token.FileSet
	// tlsPkgs holds the local names bound to crypto/tls in this file — "tls"
	// normally, or an alias. Empty when the file does not import crypto/tls,
	// in which case no expression in it can be a crypto/tls constant.
	tlsPkgs map[string]bool
	// elided holds inner composite literals whose type Go elides because the
	// enclosing slice, array or map declares it: the `{...}` in
	// `[]tls.Config{{...}}` has a nil Type of its own. ast.Inspect visits the
	// parent first, so the parent records its children here and they are still
	// recognised as tls.Config when their turn comes.
	elided map[ast.Node]bool
	out    []findings.Finding
}

func (s *scanner) visit(n ast.Node) bool {
	switch node := n.(type) {
	case *ast.CompositeLit:
		s.checkCompositeLit(node)
	case *ast.AssignStmt:
		s.checkAssign(node)
	}
	return true
}

// checkCompositeLit handles the `tls.Config{...}` construction form, including
// `&tls.Config{...}` (the & is a UnaryExpr wrapping this node) and configs
// nested inside another literal such as `&http.Transport{TLSClientConfig: ...}`.
func (s *scanner) checkCompositeLit(lit *ast.CompositeLit) {
	isTLSConfig := s.elided[lit] || s.isTLSConfigType(lit.Type)
	s.markElidedElements(lit)

	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok {
			continue
		}
		switch key.Name {
		case "InsecureSkipVerify":
			// Only the literal true. A variable is not resolvable here and is
			// deliberately not reported — KNOWN LIMITS (1).
			if isTrueLiteral(kv.Value) {
				s.add(ruleInsecureSkipVerify, kv, isTLSConfig)
			}
		case "MinVersion":
			// MinVersion is a generic-sounding field name that other libraries
			// use for unrelated things (API versions, protocol revisions), so
			// a bare integer only counts inside a literal known to be a
			// tls.Config. A tls.VersionTLS10 constant anchors itself to
			// crypto/tls and is reported wherever it appears.
			if s.isWeakTLSVersion(kv.Value, isTLSConfig) {
				s.add(ruleWeakTLSVersion, kv, isTLSConfig)
			}
		}
	}
}

// checkAssign handles the post-construction form, which is how the setting is
// most often slipped in later:
//
//	cfg := &tls.Config{}
//	cfg.InsecureSkipVerify = true
func (s *scanner) checkAssign(as *ast.AssignStmt) {
	for i, lhs := range as.Lhs {
		sel, ok := lhs.(*ast.SelectorExpr)
		if !ok || i >= len(as.Rhs) {
			continue
		}
		rhs := as.Rhs[i]
		switch sel.Sel.Name {
		case "InsecureSkipVerify":
			if isTrueLiteral(rhs) {
				// The receiver's type is unknown without go/types, so this is
				// reported at Medium confidence — see add().
				s.add(ruleInsecureSkipVerify, as, false)
			}
		case "MinVersion":
			// Only the named crypto/tls constants: an assignment gives no type
			// context at all, so a bare integer here would be a guess.
			if s.isWeakTLSVersion(rhs, false) {
				s.add(ruleWeakTLSVersion, as, true)
			}
		}
	}
}

// isTLSConfigType reports whether a composite-literal type expression denotes
// crypto/tls.Config, resolving the local import name.
func (s *scanner) isTLSConfigType(expr ast.Expr) bool {
	switch t := expr.(type) {
	case *ast.SelectorExpr:
		pkg, ok := t.X.(*ast.Ident)
		return ok && s.tlsPkgs[pkg.Name] && t.Sel.Name == "Config"
	case *ast.StarExpr:
		return s.isTLSConfigType(t.X)
	}
	return false
}

// markElidedElements records the children of a `[]tls.Config{{...}}`-style
// literal so they are recognised as tls.Config despite carrying no type of
// their own.
func (s *scanner) markElidedElements(lit *ast.CompositeLit) {
	var elem ast.Expr
	switch t := lit.Type.(type) {
	case *ast.ArrayType:
		elem = t.Elt
	case *ast.MapType:
		elem = t.Value
	default:
		return
	}
	if !s.isTLSConfigType(elem) {
		return
	}
	for _, elt := range lit.Elts {
		// A map literal's elements are key/value pairs; the value is the one
		// with the elided type.
		if kv, ok := elt.(*ast.KeyValueExpr); ok {
			elt = kv.Value
		}
		if inner, ok := elt.(*ast.CompositeLit); ok && inner.Type == nil {
			s.elided[inner] = true
		}
	}
}

// weakVersionConsts are the crypto/tls version constants below TLS 1.2.
var weakVersionConsts = map[string]bool{
	"VersionTLS10": true,
	"VersionTLS11": true,
	// SSL 3.0 is worse still (POODLE) and Go has removed support, but the
	// constant remains and legacy code still names it.
	"VersionSSL30": true,
}

// weakVersionValues are the same versions written as raw numbers, in both the
// hex form the RFCs use and the decimal form a linter-shy codebase sometimes
// substitutes. Only trusted inside a known tls.Config.
var weakVersionValues = map[string]bool{
	"0x0300": true, "768": true, // SSL 3.0
	"0x0301": true, "769": true, // TLS 1.0
	"0x0302": true, "770": true, // TLS 1.1
}

// isWeakTLSVersion reports whether an expression names a TLS version below 1.2.
// Raw numeric literals only count when the surrounding literal is known to be a
// tls.Config; a named crypto/tls constant is self-identifying.
func (s *scanner) isWeakTLSVersion(expr ast.Expr, allowRawNumber bool) bool {
	switch v := expr.(type) {
	case *ast.SelectorExpr:
		pkg, ok := v.X.(*ast.Ident)
		return ok && s.tlsPkgs[pkg.Name] && weakVersionConsts[v.Sel.Name]
	case *ast.BasicLit:
		if !allowRawNumber || v.Kind != token.INT {
			return false
		}
		return weakVersionValues[strings.ToLower(v.Value)]
	}
	return false
}

// isTrueLiteral reports whether an expression is the identifier true.
//
// Only the literal counts. `false` is an *ast.Ident too, and this is where it
// is rejected — the whole point of parsing rather than pattern-matching.
func isTrueLiteral(expr ast.Expr) bool {
	id, ok := expr.(*ast.Ident)
	return ok && id.Name == "true"
}

// add records a finding at the node's position.
//
// confirmedType carries whether the enclosing type was proven to be
// crypto/tls.Config. When it was not, the detection rests on the field name
// alone: a wrapper struct with its own InsecureSkipVerify field, or a
// post-construction assignment whose receiver type needs go/types to resolve.
// Those are still reported — a Go field named InsecureSkipVerify set to true
// has one meaning, and library wrappers pass it straight through to
// crypto/tls — but at Medium confidence, so a reviewer can tell the two apart.
func (s *scanner) add(ruleID string, node ast.Node, confirmedType bool) {
	pos := s.fset.Position(node.Pos())
	end := s.fset.Position(node.End())

	confidence := findings.ConfidenceHigh
	message := "TLS certificate verification is disabled (InsecureSkipVerify: true)"
	cwe := "CWE-295"
	severity := findings.SeverityHigh
	if ruleID == ruleWeakTLSVersion {
		message = "TLS minimum version is set below TLS 1.2"
		cwe = "CWE-327"
		severity = findings.SeverityMedium
	}
	if !confirmedType {
		confidence = findings.ConfidenceMedium
		message += " on a struct that could not be confirmed to be a crypto/tls.Config"
	}

	s.out = append(s.out, findings.Finding{
		RuleID:     ruleID,
		Severity:   severity,
		Confidence: confidence,
		Message:    message,
		Location: findings.Location{
			FilePath:    s.path,
			StartLine:   pos.Line,
			EndLine:     end.Line,
			StartColumn: pos.Column,
			EndColumn:   end.Column,
		},
		Metadata: map[string]string{"cwe": cwe, "gosec": "G402"},
	})
}

// isTestPath reports whether a path is Go test code or a test fixture tree.
