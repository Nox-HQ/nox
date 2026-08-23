// Package fileperms detects files and directories created with a
// world-writable permission mode.
//
// WHY THIS IS ITS OWN ANALYZER. Like weakcrypto, this is dangerous *API usage*
// rather than a taint flow: `os.WriteFile(p, b, 0o777)` is wrong regardless of
// where `p` or `b` came from, so there is no source to track and the taint
// engine has nothing to say about it. It covers the gosec families G301
// (MkdirAll), G302 (Chmod) and G306 (WriteFile), which a fleet that has dropped
// gosec in favour of nox otherwise loses entirely (#405).
//
// SCOPE, deliberately narrow — this analyzer follows weakcrypto's stated
// philosophy, because file modes are exactly the kind of ubiquitous stdlib call
// that gets a rule globally suppressed when it over-fires.
//
// THRESHOLD: the world-writable bit (mode & 0o002) only.
//
// gosec's defaults are 0600 for files and 0750 for directories, so under gosec
// `os.WriteFile(p, b, 0o644)` and `os.MkdirAll(p, 0o755)` are both findings.
// Those two modes are the normal, correct, idiomatic defaults in Go code — they
// are what `go` itself writes — so a rule that reports them reports most of the
// file writes in most repositories. That is not a vulnerability signal, it is a
// preference, and it is measurably the reason gosec's permission rules are
// among the most-suppressed in the fleet.
//
// World-writable is different in kind. Any local user — any other container in
// a shared mount, any compromised low-privilege process — can rewrite the
// contents. If the file is a script, a config, a plugin, a lockfile or a
// credential, that is straightforward code or policy injection; for a directory
// it also means an attacker can replace entries underneath a path your code
// trusts. There is no idiom that needs it, so unlike 0644 there is no
// legitimate-majority case to weigh against, and the finding is actionable
// without knowing anything about the file's contents.
//
// World-READABLE (0o004) is therefore deliberately NOT flagged. Whether
// 0o644 is wrong depends entirely on what is in the file, which this analyzer
// cannot see; flagging it would put the rule back in the suppress-it-globally
// category for no gain. Group-writable (0o020) is likewise left alone: it is a
// deliberate, common pattern for a shared service group.
//
// STICKY. A world-writable directory carrying os.ModeSticky is the /tmp
// pattern: anyone may create entries, but only an entry's owner may remove or
// rename it. That is a deliberate design, not an oversight, so an explicit
// `| os.ModeSticky` suppresses the finding.
//
// WHAT IT CANNOT SEE. The mode must be a literal in the call. A named constant
// (`os.MkdirAll(p, dirPerm)`) needs go/types to resolve and is not reported —
// under-reporting is the correct failure direction here. Methods are not
// matched either: `f.Chmod(0o777)` on an *os.File would need the receiver's
// type, and matching a bare `.Chmod(` would flag every unrelated Chmod-shaped
// method in the tree.
package fileperms

import (
	"context"
	"fmt"
	"go/ast"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/nox-hq/nox/core/source"

	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/rules"
)

// Analyzer reports world-writable file and directory modes in Go source.
type Analyzer struct{}

// NewAnalyzer constructs the file-permission analyzer.
func NewAnalyzer() *Analyzer { return &Analyzer{} }

// Rule IDs this analyzer emits. Files and directories are separate IDs so a
// team can waive one without waiving the other — the remediation differs, and
// so does the exposure.
const (
	ruleFile = "PERM-001"
	ruleDir  = "PERM-002"
)

// worldWrite is the permission bit that decides every finding here.
const worldWrite = 0o002

// kind distinguishes what the flagged call creates, which selects the rule ID
// and the remediation.
type kind int

const (
	kindFile kind = iota
	kindDir
)

// call describes one stdlib entry point that takes a permission mode.
//
// arity is checked exactly. It is what keeps a same-named helper in the scanned
// project — a local `os` shadow, or a wrapper with a different signature — from
// being read as the stdlib call with the mode in a different position.
type call struct {
	kind   kind
	modeAt int // index of the permission argument
	arity  int // exact number of arguments the stdlib function takes
}

// modeCalls maps `pkg.Func` to where its permission argument lives.
//
// io/ioutil is included because it is deprecated, not gone: it remains common
// in fleet code that predates Go 1.16, and ioutil.WriteFile's mode argument is
// as real as os.WriteFile's.
var modeCalls = map[string]call{
	"os.WriteFile":     {kindFile, 2, 3},
	"ioutil.WriteFile": {kindFile, 2, 3},
	"os.OpenFile":      {kindFile, 2, 3},
	"os.Chmod":         {kindFile, 1, 2},
	"os.Mkdir":         {kindDir, 1, 2},
	"os.MkdirAll":      {kindDir, 1, 2},
}

// Rules returns the rules this analyzer can emit, for the rule catalogue.
func (a *Analyzer) Rules() *rules.RuleSet {
	rs := rules.NewRuleSet()
	rs.Add(&rules.Rule{
		ID:          ruleFile,
		Version:     "1.0",
		Description: "File created or chmod'd with a world-writable permission mode",
		// Medium, matching gosec's own rating for this family. A world-writable
		// file is a genuine defect, but exploiting it requires an attacker to
		// already have local access, and on a single-tenant container there may
		// be no second principal at all. High is reserved for conditions that
		// are exploitable from outside.
		Severity: findings.SeverityMedium,
		// High: unlike weakcrypto, there is no ambiguity about intent. The mode
		// is a literal in the call, and no correct use of these APIs needs the
		// world-write bit.
		Confidence: findings.ConfidenceHigh,
		Tags:       []string{"permissions", "hardening", "gosec-g302", "gosec-g306", "owasp-a01"},
		Remediation: "This writes a file that any local user can modify. If the file holds configuration, credentials, a script, or anything else the process later trusts, an attacker with any local account can replace its contents. " +
			"Drop the world-write bit: 0o600 for data only this process should read, 0o644 where other users legitimately need to read it. " +
			"If a second process genuinely needs write access, grant it through group ownership (0o660) rather than to everyone.",
		References: []string{
			"https://cwe.mitre.org/data/definitions/732.html",
			"https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
		},
		Metadata: map[string]string{"cwe": "CWE-732"},
	})
	rs.Add(&rules.Rule{
		ID:          ruleDir,
		Version:     "1.0",
		Description: "Directory created with a world-writable permission mode and no sticky bit",
		Severity:    findings.SeverityMedium,
		Confidence:  findings.ConfidenceHigh,
		Tags:        []string{"permissions", "hardening", "gosec-g301", "owasp-a01"},
		Remediation: "This creates a directory any local user can write to, so an attacker can add, replace, or delete entries under a path this program treats as its own — including swapping a file the program later reads or executes. " +
			"Use 0o700 for a private directory or 0o755 where others need to list it. " +
			"If the directory is deliberately a shared drop point, add os.ModeSticky (the /tmp model) so only an entry's owner can remove or rename it.",
		References: []string{
			"https://cwe.mitre.org/data/definitions/732.html",
			"https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
		},
		Metadata: map[string]string{"cwe": "CWE-732"},
	})
	return rs
}

// ScanArtifacts reports world-writable modes across discovered Go sources.
func (a *Analyzer) ScanArtifacts(ctx context.Context, artifacts []discovery.Artifact) (*findings.FindingSet, error) {
	fs := findings.NewFindingSet()

	for _, art := range artifacts {
		if err := ctx.Err(); err != nil {
			return fs, err
		}
		if !strings.EqualFold(filepath.Ext(art.Path), ".go") {
			continue
		}
		// Test files and fixtures are skipped, as in weakcrypto. Test trees are
		// where deliberate 0o777 lives — a scanner's own permission fixtures
		// included — and flagging them trains people to ignore the rule.
		if source.IsTestPath(art.Path) {
			continue
		}

		content, err := os.ReadFile(art.AbsPath)
		if err != nil {
			// Unreadable file is not a finding; discovery already surfaced it.
			continue
		}
		for _, f := range scanSource(art.Path, content) {
			fs.Add(f)
		}
	}
	return fs, nil
}

// scanSource parses one Go file and returns its findings.
func scanSource(path string, content []byte) []findings.Finding {
	file, fset := source.ParseGoFile(path, content)
	if file == nil {
		return nil
	}

	var out []findings.Finding
	ast.Inspect(file, func(n ast.Node) bool {
		ce, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		name, ok := calleeName(ce.Fun)
		if !ok {
			return true
		}
		spec, ok := modeCalls[name]
		if !ok || len(ce.Args) != spec.arity {
			return true
		}
		mode, ok := evalMode(ce.Args[spec.modeAt])
		if !ok || mode.bits&worldWrite == 0 {
			return true
		}
		// Sticky is the deliberate /tmp pattern: world-writable by design, with
		// removal still restricted to the entry's owner. Only os.ModeSticky
		// counts — a raw 0o1777 literal does NOT set it, because os.Mkdir masks
		// the numeric mode with Perm() (0o777) and takes the sticky bit solely
		// from Go's ModeSticky (1<<20). So 0o1777 is still a finding, correctly.
		if mode.sticky {
			return true
		}

		pos := fset.Position(ce.Args[spec.modeAt].Pos())
		ruleID, what := ruleFile, "file"
		if spec.kind == kindDir {
			ruleID, what = ruleDir, "directory"
		}
		// Chmod does not create anything, it re-modes an existing path; saying
		// "creates" there would misdescribe the call the reader is looking at.
		msg := fmt.Sprintf("%s creates a world-writable %s (mode %s)",
			name, what, formatMode(mode.bits))
		if name == "os.Chmod" {
			msg = fmt.Sprintf("%s makes a %s world-writable (mode %s)",
				name, what, formatMode(mode.bits))
		}
		out = append(out, findings.Finding{
			RuleID:     ruleID,
			Severity:   findings.SeverityMedium,
			Confidence: findings.ConfidenceHigh,
			Message:    msg,
			Location: findings.Location{
				FilePath:  path,
				StartLine: pos.Line,
				EndLine:   pos.Line,
			},
			Metadata: map[string]string{
				"cwe":  "CWE-732",
				"call": name,
				"mode": formatMode(mode.bits),
			},
		})
		return true
	})
	return out
}

// calleeName renders a `pkg.Func` callee as "pkg.Func". Anything else — a bare
// identifier, a method on a value, a deeper selector chain — returns false, so
// only package-qualified stdlib calls are ever considered.
func calleeName(fun ast.Expr) (string, bool) {
	sel, ok := fun.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok {
		return "", false
	}
	return pkg.Name + "." + sel.Sel.Name, true
}

// mode is a partially-evaluated permission expression.
type mode struct {
	bits   uint64
	sticky bool
}

// evalMode evaluates a permission argument far enough to decide whether the
// world-write bit is set.
//
// It handles the forms that actually appear: an octal literal in either
// spelling (0777, 0o777), a conversion (os.FileMode(0777), fs.FileMode(0o777)),
// and an OR chain combining a literal with mode constants. It reports ok=false
// whenever the value cannot be pinned down, which is the safe direction: an
// unknown mode produces no finding.
func evalMode(e ast.Expr) (mode, bool) {
	switch v := e.(type) {
	case *ast.ParenExpr:
		return evalMode(v.X)

	case *ast.BasicLit:
		if v.Kind != token.INT {
			return mode{}, false
		}
		// Base 0 honours Go's own literal syntax, so 0777, 0o777, 0x1ff and a
		// plain decimal are each read as the compiler reads them. A decimal
		// literal is not a mistake to correct here: `os.Chmod(p, 666)` really
		// does request 0o1232, which really is world-writable.
		n, err := strconv.ParseUint(strings.ReplaceAll(v.Value, "_", ""), 0, 64)
		if err != nil {
			return mode{}, false
		}
		return mode{bits: n}, true

	case *ast.SelectorExpr:
		// os.ModeSticky / fs.ModeSticky. Other Mode* constants (ModeDir,
		// ModeSetuid, …) carry no permission bits, so they contribute nothing
		// but must still count as "known" or an OR chain containing one would
		// be discarded.
		if !strings.HasPrefix(v.Sel.Name, "Mode") {
			return mode{}, false
		}
		return mode{sticky: v.Sel.Name == "ModeSticky"}, true

	case *ast.CallExpr:
		// A conversion: os.FileMode(0777), fs.FileMode(0o777), FileMode(0777).
		if len(v.Args) != 1 || !isFileModeConversion(v.Fun) {
			return mode{}, false
		}
		return evalMode(v.Args[0])

	case *ast.BinaryExpr:
		if v.Op != token.OR {
			// &^ and & can CLEAR the world-write bit (0o777 &^ 0o022), so any
			// operator other than OR is treated as unknown rather than guessed.
			return mode{}, false
		}
		l, lok := evalMode(v.X)
		r, rok := evalMode(v.Y)
		if !lok && !rok {
			return mode{}, false
		}
		// OR only ever adds bits, so a known side is still conclusive when the
		// other side is opaque: if the literal half already sets world-write,
		// the result does too whatever the unknown half holds.
		//
		// The converse does NOT hold — an opaque operand may carry the bit
		// itself, as in the tar-extraction idiom `hdr.Mode&0o777|0o755`, whose
		// result is world-writable exactly when the archive entry was. Staying
		// silent there is a deliberate under-report: the alternative flags every
		// use of a hardening idiom whose whole point is to clamp the mode.
		return mode{bits: l.bits | r.bits, sticky: l.sticky || r.sticky}, true
	}
	return mode{}, false
}

// isFileModeConversion reports whether fun is os.FileMode / fs.FileMode or a
// bare FileMode identifier (dot-imported io/fs).
func isFileModeConversion(fun ast.Expr) bool {
	switch f := fun.(type) {
	case *ast.Ident:
		return f.Name == "FileMode"
	case *ast.SelectorExpr:
		return f.Sel.Name == "FileMode"
	}
	return false
}

// formatMode renders the permission bits the way the source spelled them, so
// the message can be matched against the code by eye.
func formatMode(bits uint64) string {
	return "0" + strconv.FormatUint(bits&0o7777, 8)
}

// isTestPath reports whether a path is Go test code or a fixture tree.
