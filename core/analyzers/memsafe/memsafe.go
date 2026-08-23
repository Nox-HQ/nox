// Package memsafe detects integer-overflow truncation that reaches a memory
// sizing operation in Go source.
//
// WHY THIS IS ITS OWN ANALYZER. It is not a taint flow — the danger is the
// arithmetic, not the provenance, and the value need not come from a tracked
// source to wrap. It is not weak crypto and it is not a secret. It is a
// property of a *conversion expression and what it feeds*, which nothing in
// core previously modelled.
//
// SCOPE, DELIBERATELY MUCH NARROWER THAN gosec G115. This rule exists because
// gosec was removed from the fleet's shared golangci config, leaving integer
// conversions uncovered. Measuring gosec's own G115 across sixteen Go
// repositories plus nox itself produced 96 findings and, on inspection, zero
// true positives: `int32(len(out))` and `int32(total)` filling protobuf count
// fields, `uint64(t.Unix())` in an HOTP counter, `byte(addr>>24)` extracting an
// IPv4 octet, `byte(nano%10)` formatting a digit. Truncation is very often the
// programmer's intent, and a rule that cannot tell intent from accident gets
// globally suppressed — which is exactly what happened: 63 `#nosec G115`
// suppressions already exist in that fleet.
//
// So this analyzer does NOT report every narrowing conversion. It reports the
// one shape where truncation is a memory-safety bug rather than a style
// question: a value that is narrowed (or flipped signed→unsigned) and then used
// to SIZE AN ALLOCATION or BOUND A SLICE — `make([]byte, n)`, `buf[n]`,
// `buf[:n]`. That is CWE-190 turning into CWE-680/CWE-789: the wrapped length
// either panics or, worse, allocates and indexes a buffer that does not match
// the length the rest of the code believes in. A truncated counter in a
// response message is not that, and is not reported.
//
// The conversion must also be UNGUARDED: a preceding bounds comparison, a bit
// mask, or a modulo that provably fits the destination all suppress it, because
// each of those is the correct fix and code that already applies one is not
// vulnerable.
//
// TYPE INFORMATION. nox parses Go with go/ast only — no go/types — because
// type checking requires a resolvable module graph and a Go toolchain, neither
// of which nox can assume when it scans a checked-out tree offline. Source
// types are therefore inferred from declarations visible in the same function:
// parameters, results, `var` declarations, explicit conversions, and a small
// table of standard-library functions with fixed integer return types. A
// conversion whose operand type cannot be established locally is NOT reported.
// That is a deliberate false-negative trade: silence beats a guess.
// See docs/design/go-integer-overflow.md.
package memsafe

import (
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

// Analyzer reports unvalidated narrowing integer conversions that size memory.
type Analyzer struct{}

// NewAnalyzer constructs the memory-safety analyzer.
func NewAnalyzer() *Analyzer { return &Analyzer{} }

// ruleID is the single rule this analyzer emits.
const ruleID = "MEMSAFE-001"

// Rules returns the rule this analyzer can emit, for the rule catalogue.
func (a *Analyzer) Rules() *rules.RuleSet {
	rs := rules.NewRuleSet()
	rs.Add(&rules.Rule{
		ID:          ruleID,
		Version:     "1.0",
		Description: "Integer truncation reaching an allocation size or slice bound (CWE-190)",
		Severity:    findings.SeverityMedium,
		// Medium: the conversion and the sink are both established
		// syntactically and the guard analysis suppresses the safe forms, but
		// whether the operand can actually exceed the destination's range
		// depends on callers this analyzer does not see.
		Confidence: findings.ConfidenceMedium,
		Tags:       []string{"go", "integer-overflow", "memory-safety", "cwe-190"},
		Remediation: "A value is narrowed to a smaller integer type — or converted from signed to unsigned — and the result is then used to size an allocation or bound a slice. " +
			"If the original value exceeds the destination's range it wraps: a large length becomes a small one, and a negative length becomes an enormous unsigned one. " +
			"The consequence is a panic at best and a buffer whose size disagrees with the length the surrounding code assumes at worst. " +
			"Fix it by range-checking before the conversion (`if n < 0 || n > math.MaxInt32 { return err }`), by masking to the destination width when truncation is intended (`v & 0xFF`), or by keeping the wider type all the way to the allocation. " +
			"If the value is provably bounded by something this analyzer cannot see, suppress with a nox:ignore comment recording the bound.",
		References: []string{
			"https://cwe.mitre.org/data/definitions/190.html",
			"https://cwe.mitre.org/data/definitions/680.html",
		},
		Metadata: map[string]string{"cwe": "CWE-190"},
	})
	return rs
}

// ScanArtifacts reports truncating conversions that size memory, across
// discovered Go sources.
func (a *Analyzer) ScanArtifacts(ctx context.Context, artifacts []discovery.Artifact) (*findings.FindingSet, error) {
	fs := findings.NewFindingSet()

	for _, art := range artifacts {
		if err := ctx.Err(); err != nil {
			return fs, err
		}
		if !strings.EqualFold(filepath.Ext(art.Path), ".go") {
			continue
		}
		// Test files are skipped: fixtures deliberately construct overflowing
		// conversions (including this analyzer's own tests), and flagging them
		// trains people to ignore the rule.
		if source.IsTestPath(art.Path) {
			continue
		}

		content, err := os.ReadFile(art.AbsPath)
		if err != nil {
			// Unreadable file is not a finding; discovery already surfaced it.
			continue
		}
		// Generated code is skipped. Every one of the twenty gosec `unsafe`
		// findings measured across this fleet sat in protoc-gen-go output, and
		// a rule that reports code nobody writes is pure noise. The marker is
		// the convention from https://go.dev/s/generatedcode.
		if source.IsGenerated(content) {
			continue
		}

		for _, f := range scanFile(art.Path, content) {
			fs.Add(f)
		}
	}
	return fs, nil
}

// scanFile parses one Go source and returns its findings. A file that does not
// parse yields whatever the recovered partial AST supports rather than an
// error: a non-compiling snippet must degrade, never crash the scan.
func scanFile(path string, content []byte) []findings.Finding {
	file, fset := source.ParseGoFile(path, content)
	if file == nil {
		return nil
	}

	var out []findings.Finding
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		out = append(out, (&funcScan{fset: fset, path: path, fn: fn}).run()...)
	}
	return out
}

// funcScan holds the per-function analysis state. Everything this analyzer
// knows is function-local by construction: package-level and cross-package
// types are not resolvable without go/types (see the package comment).
type funcScan struct {
	fset *token.FileSet
	path string
	fn   *ast.FuncDecl

	// types maps a local name to the integer type it was declared or inferred
	// to have. Absent means "unknown", which suppresses reporting.
	types map[string]intKind
	// guarded holds names that are compared against a bound somewhere in this
	// function. Presence suppresses reporting for that name: the code already
	// does the thing the rule would ask for.
	guarded map[string]bool
	// bounds holds, for names that are masked or reduced modulo a constant
	// somewhere in this function, the tightest magnitude bound observed. It is
	// checked against the DESTINATION type at report time, so `x & 0xFF`
	// suppresses a conversion to uint8 but `x & 0xFFFF` does not. Where a name
	// is bounded more than once the smallest bound wins: this rule errs toward
	// silence, and a mask in one branch is nearly always the same mask in all.
	bounds map[string]uint64
	// sinks holds names that appear in an allocation-size or slice-bound
	// position somewhere in this function.
	sinks map[string]bool
}

func (s *funcScan) run() []findings.Finding {
	s.types = map[string]intKind{}
	s.guarded = map[string]bool{}
	s.bounds = map[string]uint64{}
	s.sinks = map[string]bool{}

	s.collectDeclaredTypes()
	s.collectGuards()
	s.collectSinks()
	return s.report()
}

// ---------------------------------------------------------------------------
// Integer type lattice
// ---------------------------------------------------------------------------

// intKind is a Go integer type reduced to the only two properties that decide
// whether a conversion can lose information.
type intKind struct {
	bits   int  // 8, 16, 32 or 64
	signed bool // true for intN / int, false for uintN / uint / uintptr
}

// intTypes maps every predeclared integer type name to its kind. `int`, `uint`
// and `uintptr` are taken as 64-bit: that is true on every platform the fleet
// builds for, and assuming 64 is the conservative choice — it makes int→int32
// a narrowing (reportable) rather than a no-op.
var intTypes = map[string]intKind{
	"int8":    {8, true},
	"int16":   {16, true},
	"int32":   {32, true},
	"rune":    {32, true},
	"int64":   {64, true},
	"int":     {64, true},
	"uint8":   {8, false},
	"byte":    {8, false},
	"uint16":  {16, false},
	"uint32":  {32, false},
	"uint64":  {64, false},
	"uint":    {64, false},
	"uintptr": {64, false},
}

// lossy reports whether converting a value of kind from to kind to can change
// its value, and returns a short human-readable reason.
//
// Three ways to lose information, and one deliberate non-case:
//   - narrowing: fewer bits in the destination, same signedness.
//   - signed → unsigned: a negative value becomes an enormous positive one,
//     at any width. This is the form that turns a length check inside out.
//   - unsigned → signed at the same or smaller width: the top half of the
//     source range becomes negative.
//
// Widening with the same signedness, and unsigned → signed into strictly more
// bits (uint8 → int16, uint32 → int64), are exact and never reported.
func lossy(from, to intKind) (string, bool) {
	switch {
	case from == to:
		return "", false
	case from.signed && !to.signed:
		return "signed to unsigned", true
	case !from.signed && to.signed:
		if to.bits > from.bits {
			return "", false // uint8 -> int16 and friends are exact
		}
		return "unsigned to signed", true
	case to.bits < from.bits:
		return "truncating", true
	default:
		return "", false
	}
}

// ---------------------------------------------------------------------------
// Local type inference
// ---------------------------------------------------------------------------

// stdReturns maps a standard-library call, rendered as a dotted chain, to the
// integer type it returns. Only functions whose return type is fixed by the
// language or the standard library appear here, so a match is a fact rather
// than a heuristic. Method-suffix keys are deliberately absent: `.Size()` and
// `.Len()` exist on unrelated types with unrelated widths, and guessing there
// is how a rule starts lying.
var stdReturns = map[string]intKind{
	"len":                 {64, true}, // int
	"cap":                 {64, true}, // int
	"strconv.Atoi":        {64, true}, // int
	"strconv.ParseInt":    {64, true}, // int64
	"strconv.ParseUint":   {64, false},
	"os.Getpid":           {64, true},
	"os.Getppid":          {64, true},
	"rand.Int":            {64, true},
	"rand.Int63":          {64, true},
	"rand.Int63n":         {64, true},
	"rand.Uint64":         {64, false},
	"rand.Uint32":         {32, false},
	"rand.Int31":          {32, true},
	"rand.Int31n":         {32, true},
	"BigEndian.Uint16":    {16, false},
	"BigEndian.Uint32":    {32, false},
	"BigEndian.Uint64":    {64, false},
	"LittleEndian.Uint16": {16, false},
	"LittleEndian.Uint32": {32, false},
	"LittleEndian.Uint64": {64, false},
	"NativeEndian.Uint16": {16, false},
	"NativeEndian.Uint32": {32, false},
	"NativeEndian.Uint64": {64, false},
	"time.Now.Unix":       {64, true},
	"time.Now.UnixNano":   {64, true},
	"time.Now.UnixMilli":  {64, true},
	"time.Now.UnixMicro":  {64, true},
}

// collectDeclaredTypes records the integer type of every function-scoped name
// whose type is written down or directly inferable.
func (s *funcScan) collectDeclaredTypes() {
	record := func(names []*ast.Ident, typ ast.Expr) {
		k, ok := identKind(typ)
		if !ok {
			return
		}
		for _, n := range names {
			if n != nil && n.Name != "_" {
				s.types[n.Name] = k
			}
		}
	}

	// Receiver, parameters and named results: their types are written in the
	// signature, so they are the most reliable source there is.
	for _, fl := range []*ast.FieldList{s.fn.Recv, s.fn.Type.Params, s.fn.Type.Results} {
		if fl == nil {
			continue
		}
		for _, f := range fl.List {
			record(f.Names, f.Type)
		}
	}

	ast.Inspect(s.fn.Body, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.DeclStmt:
			gd, ok := v.Decl.(*ast.GenDecl)
			if !ok {
				return true
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				if vs.Type != nil {
					record(vs.Names, vs.Type)
					continue
				}
				// `var x = <expr>` and `x := <expr>` share the inference path.
				for i, name := range vs.Names {
					if i < len(vs.Values) {
						s.inferAssign(name, vs.Values[i])
					}
				}
			}
		case *ast.AssignStmt:
			if len(v.Lhs) == len(v.Rhs) {
				for i, lhs := range v.Lhs {
					if id, ok := lhs.(*ast.Ident); ok {
						s.inferAssign(id, v.Rhs[i])
					}
				}
				return true
			}
			// `n, err := strconv.ParseInt(...)` — one call feeding several
			// names. Every entry in stdReturns returns its integer FIRST
			// (`(int64, error)`, `(int, error)`), so the first name takes the
			// tabled kind and the rest stay unknown. Any other multi-value
			// call would need the callee's full signature, which is exactly
			// what go/types would provide and this does not have.
			if len(v.Rhs) != 1 || len(v.Lhs) == 0 {
				return true
			}
			call, ok := v.Rhs[0].(*ast.CallExpr)
			if !ok {
				return true
			}
			if k, ok := stdReturns[chainOf(call.Fun)]; ok {
				if id, ok := v.Lhs[0].(*ast.Ident); ok && id.Name != "_" {
					s.types[id.Name] = k
				}
			}
		}
		return true
	})
}

// inferAssign records the type of name when the right-hand side determines it.
func (s *funcScan) inferAssign(name *ast.Ident, rhs ast.Expr) {
	if name == nil || name.Name == "_" {
		return
	}
	if k, ok := s.exprKind(rhs); ok {
		s.types[name.Name] = k
	}
}

// identKind maps a type expression to an integer kind, for the predeclared
// integer types only. A named type (`os.FileMode`, `time.Duration`, a local
// `type ID uint32`) returns false: resolving its underlying type is precisely
// what needs go/types.
func identKind(e ast.Expr) (intKind, bool) {
	id, ok := e.(*ast.Ident)
	if !ok {
		return intKind{}, false
	}
	k, ok := intTypes[id.Name]
	return k, ok
}

// exprKind infers the integer kind of an expression from local information.
// The second result is false whenever the type cannot be established, which is
// the common case and always means "do not report".
func (s *funcScan) exprKind(e ast.Expr) (intKind, bool) {
	switch v := e.(type) {
	case *ast.ParenExpr:
		return s.exprKind(v.X)
	case *ast.Ident:
		k, ok := s.types[v.Name]
		return k, ok
	case *ast.CallExpr:
		// A conversion to a predeclared integer type yields that type.
		if k, ok := identKind(v.Fun); ok {
			return k, true
		}
		if k, ok := stdReturns[chainOf(v.Fun)]; ok {
			return k, true
		}
		return intKind{}, false
	case *ast.BinaryExpr:
		// Both operands of a Go binary op share one type, so either side that
		// is known determines the result. Shifts are the exception: the result
		// takes the LEFT operand's type regardless of the right.
		if v.Op == token.SHL || v.Op == token.SHR {
			return s.exprKind(v.X)
		}
		if k, ok := s.exprKind(v.X); ok {
			return k, true
		}
		return s.exprKind(v.Y)
	case *ast.UnaryExpr:
		return s.exprKind(v.X)
	}
	return intKind{}, false
}

// chainOf renders a selector expression as the dotted string the stdReturns
// table is keyed on, dropping call parentheses — the same convention the Go
// taint extractor uses. `binary.BigEndian.Uint32` renders as
// `BigEndian.Uint32` after the leading package qualifier is dropped by the
// two-segment suffix rule below, and `time.Now().Unix()` renders as
// `time.Now.Unix`.
func chainOf(e ast.Expr) string {
	var parts []string
	var walk func(ast.Expr) bool
	walk = func(x ast.Expr) bool {
		switch v := x.(type) {
		case *ast.Ident:
			parts = append(parts, v.Name)
			return true
		case *ast.SelectorExpr:
			if !walk(v.X) {
				return false
			}
			parts = append(parts, v.Sel.Name)
			return true
		case *ast.CallExpr:
			return walk(v.Fun)
		case *ast.ParenExpr:
			return walk(v.X)
		}
		return false
	}
	if !walk(e) {
		return ""
	}
	full := strings.Join(parts, ".")
	if _, ok := stdReturns[full]; ok {
		return full
	}
	// Fall back to the last two segments so `binary.BigEndian.Uint32` matches
	// `BigEndian.Uint32` whatever the import is aliased to.
	if len(parts) >= 2 {
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return full
}

// ---------------------------------------------------------------------------
// Guard detection
// ---------------------------------------------------------------------------

// collectGuards marks every name the function already bounds. This runs over
// the WHOLE function rather than only the statements that dominate the
// conversion: a coarse over-approximation whose only failure mode is silence,
// which is the direction this rule errs in on purpose.
func (s *funcScan) collectGuards() {
	ast.Inspect(s.fn.Body, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.BinaryExpr:
			switch v.Op {
			case token.LSS, token.GTR, token.LEQ, token.GEQ:
				// A comparison bounds whichever side is a plain name.
				s.markName(v.X)
				s.markName(v.Y)
			case token.AND:
				// `x & 0xFF` bounds the RESULT. Record the magnitude rather
				// than a boolean, so the suppression can be checked against
				// the destination width at report time. Only a constant
				// right-hand side counts; `x & y` bounds nothing this
				// analyzer can see.
				s.markBound(v.X, v.Y, v.Op)
			case token.REM:
				// Modulo bounds unconditionally, whatever the divisor is.
				// `h % buckHashSize` is the universal idiom for confining a
				// value to a table, and the divisor is very often a named
				// constant this analyzer cannot evaluate. Requiring a literal
				// there reported `runtime/mprof.go` and code like it; a
				// remainder is smaller than its divisor by definition, and the
				// divisor is almost always the size of the thing being
				// indexed, so treat any modulo as a bound.
				s.markName(v.X)
				s.markBound(v.X, v.Y, v.Op)
			}
		case *ast.SwitchStmt:
			// A type/value switch on a name is a bound in the same spirit as
			// a comparison; treat the tag as guarded.
			if v.Tag != nil {
				s.markName(v.Tag)
			}
		}
		return true
	})
}

// markName records a guard against a plain identifier, seeing through an
// integer conversion wrapped around it.
//
// The conversion case matters: `if uint32(r) <= MaxLatin1` is how the standard
// library range-checks a rune before narrowing it, and reading only the bare
// identifier misses every guard written that way. Anything more complex than a
// name — a field, an index, a call to something that is not a conversion — is
// not tracked, because the conversion side does not track those either.
func (s *funcScan) markName(e ast.Expr) {
	switch v := unparen(e).(type) {
	case *ast.Ident:
		s.guarded[v.Name] = true
	case *ast.CallExpr:
		if _, isConv := identKind(v.Fun); isConv && len(v.Args) == 1 {
			s.markName(v.Args[0])
		}
	}
}

// markBound records the magnitude a mask or modulo confines a name to.
func (s *funcScan) markBound(name, lit ast.Expr, op token.Token) {
	id, ok := unparen(name).(*ast.Ident)
	if !ok {
		return
	}
	limit, ok := literalBound(lit, op)
	if !ok {
		return
	}
	if prev, seen := s.bounds[id.Name]; !seen || limit < prev {
		s.bounds[id.Name] = limit
	}
}

// literalBound returns the maximum magnitude `x op lit` can produce, for the
// masking operators. `x & n` is at most n; `x % n` is at most n-1.
func literalBound(lit ast.Expr, op token.Token) (uint64, bool) {
	b, ok := unparen(lit).(*ast.BasicLit)
	if !ok || b.Kind != token.INT {
		return 0, false
	}
	v, ok := parseUintLit(b.Value)
	if !ok {
		return 0, false
	}
	if op == token.REM {
		if v == 0 {
			return 0, false
		}
		v--
	}
	return v, true
}

// isConstantish reports whether an expression is built entirely from integer
// literals, and therefore cannot overflow at runtime — the compiler would
// reject it if it did not fit.
func isConstantish(e ast.Expr) bool {
	switch v := e.(type) {
	case *ast.ParenExpr:
		return isConstantish(v.X)
	case *ast.UnaryExpr:
		return isConstantish(v.X)
	case *ast.BasicLit:
		return v.Kind == token.INT || v.Kind == token.CHAR
	case *ast.BinaryExpr:
		return isConstantish(v.X) && isConstantish(v.Y)
	}
	return false
}

// selfBounded reports whether the operand expression bounds itself, so the
// conversion cannot lose information regardless of the operand's own type.
//
// Three shapes, all of them idioms whose whole point is to make the value fit:
//   - `x & 0xFF` — a mask no wider than the destination.
//   - `x % 16` — a modulo whose remainder fits.
//   - `x >> 24` on an UNSIGNED value — a logical shift leaves at most
//     (width - shift) bits set, which is how every byte-extraction and
//     binary-search midpoint in existence is written. The shift must be
//     logical: on a signed value `>>` propagates the sign bit and bounds
//     nothing, so the source kind is required to be unsigned.
func (s *funcScan) selfBounded(e ast.Expr, to intKind) bool {
	v, ok := unparen(e).(*ast.BinaryExpr)
	if !ok {
		return false
	}
	switch v.Op {
	case token.AND, token.REM:
		limit, ok := literalBound(v.Y, v.Op)
		if !ok {
			return false
		}
		return fitsIn(limit, to)
	case token.SHR:
		from, ok := s.exprKind(v.X)
		if !ok || from.signed {
			return false
		}
		shift, ok := literalBound(v.Y, token.SHL) // reuse the literal parser
		if !ok || shift == 0 || shift >= uint64(from.bits) {
			return false
		}
		remaining := uint64(from.bits) - shift
		// The result occupies `remaining` bits, so its magnitude is at most
		// 2^remaining - 1.
		if remaining >= 64 {
			return false
		}
		return fitsIn((uint64(1)<<remaining)-1, to)
	}
	return false
}

// nonNegative reports whether an expression is provably ≥ 0 — which, for a
// signed source, removes the entire signed→unsigned hazard.
//
// Only `len` and `cap` qualify, plus arithmetic built from them and integer
// literals. Both are defined to return a non-negative count, and in a real Go
// process that count is additionally bounded by addressable memory, so
// `uint32(len(b))` cannot produce the enormous wrapped length this rule
// exists to catch. Narrowing a length to 16 bits or fewer IS still reported:
// a slice longer than 65535 is entirely ordinary.
func nonNegative(e ast.Expr) bool {
	switch v := unparen(e).(type) {
	case *ast.BasicLit:
		return v.Kind == token.INT
	case *ast.CallExpr:
		id, ok := v.Fun.(*ast.Ident)
		return ok && (id.Name == "len" || id.Name == "cap")
	case *ast.BinaryExpr:
		switch v.Op {
		case token.ADD, token.MUL, token.QUO, token.REM, token.SHL, token.SHR:
			return nonNegative(v.X) && nonNegative(v.Y)
		}
	}
	return false
}

// fitsIn reports whether every value with magnitude at most limit is
// representable in kind k.
func fitsIn(limit uint64, k intKind) bool {
	bits := uint(k.bits)
	if k.signed {
		bits--
	}
	if bits >= 64 {
		return true
	}
	return limit < (uint64(1) << bits)
}

// parseUintLit parses a Go integer literal (decimal, hex, octal, binary, with
// underscores) as an unsigned value.
func parseUintLit(s string) (uint64, bool) {
	s = strings.ReplaceAll(s, "_", "")
	base := 10
	switch {
	case strings.HasPrefix(s, "0x"), strings.HasPrefix(s, "0X"):
		s, base = s[2:], 16
	case strings.HasPrefix(s, "0b"), strings.HasPrefix(s, "0B"):
		s, base = s[2:], 2
	case strings.HasPrefix(s, "0o"), strings.HasPrefix(s, "0O"):
		s, base = s[2:], 8
	case len(s) > 1 && s[0] == '0':
		s, base = s[1:], 8
	}
	var v uint64
	if s == "" {
		return 0, false
	}
	for _, c := range s {
		var d uint64
		switch {
		case c >= '0' && c <= '9':
			d = uint64(c - '0')
		case c >= 'a' && c <= 'f':
			d = uint64(c-'a') + 10
		case c >= 'A' && c <= 'F':
			d = uint64(c-'A') + 10
		default:
			return 0, false
		}
		if d >= uint64(base) {
			return 0, false
		}
		v = v*uint64(base) + d
	}
	return v, true
}

// ---------------------------------------------------------------------------
// Sink detection
// ---------------------------------------------------------------------------

// collectSinks records every name used as an allocation size or a slice bound
// anywhere in the function, and every conversion expression used directly in
// such a position.
func (s *funcScan) collectSinks() {
	ast.Inspect(s.fn.Body, func(n ast.Node) bool {
		for _, e := range sizeOperands(n) {
			if id, ok := e.(*ast.Ident); ok {
				s.sinks[id.Name] = true
			}
		}
		return true
	})
}

// sizeOperands returns the sub-expressions of n that determine an allocation
// size or a slice bound.
//
// The set is deliberately small and each member is unambiguous:
//   - `make(T, n)` / `make(T, n, m)` — the allocation length and capacity.
//   - `s[lo:hi]`, `s[lo:hi:max]` — every slice bound.
//
// A bare INDEX expression `s[i]` is deliberately NOT a sink, for two reasons.
// Syntactically it is indistinguishable from a map lookup, where an index is
// not a bounds context at all and no value of it is wrong — telling the two
// apart needs go/types. And semantically Go bounds-checks every slice index,
// so a wrapped index panics rather than reading out of bounds; the harm is
// capped at the denial of service the slice-bound case already covers.
// Measured against the Go standard library, treating indexes as sinks
// produced 46 findings, every one of them correct code: AES S-box lookups
// (`te0[uint8(s0>>24)]`), Latin-1 property tables, and a `map[uint64]string`
// in the linker.
//
// `copy` and `append` are likewise not sinks: they are bounded by the slices
// they operate on, so a wrapped value there cannot index out of range.
func sizeOperands(n ast.Node) []ast.Expr {
	switch v := n.(type) {
	case *ast.CallExpr:
		id, ok := v.Fun.(*ast.Ident)
		if !ok || id.Name != "make" || len(v.Args) < 2 {
			return nil
		}
		return v.Args[1:]
	case *ast.SliceExpr:
		var out []ast.Expr
		for _, e := range []ast.Expr{v.Low, v.High, v.Max} {
			if e != nil {
				out = append(out, e)
			}
		}
		return out
	}
	return nil
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

// report walks the function for conversions that are lossy, unguarded, and
// reach a size sink either directly or through one local assignment.
func (s *funcScan) report() []findings.Finding {
	var out []findings.Finding
	seen := map[token.Pos]bool{}

	// Conversions sitting directly in a size position.
	ast.Inspect(s.fn.Body, func(n ast.Node) bool {
		for _, e := range sizeOperands(n) {
			if f, ok := s.check(e, "directly"); ok && !seen[e.Pos()] {
				seen[e.Pos()] = true
				out = append(out, f)
			}
		}
		return true
	})

	// Conversions assigned to a name that is later used as a size.
	ast.Inspect(s.fn.Body, func(n ast.Node) bool {
		lhs, rhs := assignPairs(n)
		for i := range lhs {
			id, ok := lhs[i].(*ast.Ident)
			if !ok || !s.sinks[id.Name] || s.guarded[id.Name] {
				continue
			}
			if f, ok := s.check(rhs[i], "through "+id.Name); ok && !seen[rhs[i].Pos()] {
				seen[rhs[i].Pos()] = true
				out = append(out, f)
			}
		}
		return true
	})
	return out
}

// assignPairs returns the 1:1 left- and right-hand sides of an assignment or
// short var declaration, or nil for anything else.
func assignPairs(n ast.Node) (lhs, rhs []ast.Expr) {
	switch v := n.(type) {
	case *ast.AssignStmt:
		if len(v.Lhs) == len(v.Rhs) {
			return v.Lhs, v.Rhs
		}
	case *ast.ValueSpec:
		if len(v.Names) == len(v.Values) {
			names := make([]ast.Expr, len(v.Names))
			for i, n := range v.Names {
				names[i] = n
			}
			return names, v.Values
		}
	}
	return nil, nil
}

// check decides whether expression e is a reportable conversion and builds the
// finding. Every early return is a reason NOT to report, and they are ordered
// cheapest first.
func (s *funcScan) check(e ast.Expr, how string) (findings.Finding, bool) {
	call, ok := unparen(e).(*ast.CallExpr)
	if !ok || len(call.Args) != 1 {
		return findings.Finding{}, false
	}
	to, ok := identKind(call.Fun)
	if !ok {
		return findings.Finding{}, false
	}
	arg := unparen(call.Args[0])

	// A constant expression cannot overflow at runtime — the compiler rejects
	// one that does not fit.
	if isConstantish(arg) {
		return findings.Finding{}, false
	}
	// The operand bounds itself: `x & 0xFF`, `x % 10`, `x >> 24`.
	if s.selfBounded(arg, to) {
		return findings.Finding{}, false
	}
	// The operand's own type must be locally provable. Unknown means silent.
	from, ok := s.exprKind(arg)
	if !ok {
		return findings.Finding{}, false
	}
	reason, bad := lossy(from, to)
	if !bad {
		return findings.Finding{}, false
	}
	// A length is non-negative and, in a live process, bounded by addressable
	// memory. Narrowing one to 32 bits or more cannot produce the wrapped
	// value this rule exists to catch, whatever the lattice says about signs.
	if to.bits >= 32 && nonNegative(arg) {
		return findings.Finding{}, false
	}
	// The function already bounds this name somewhere — either by comparison,
	// or by a mask/modulo tight enough for the destination.
	for _, n := range plainNames(arg) {
		if s.guarded[n] {
			return findings.Finding{}, false
		}
		if limit, ok := s.bounds[n]; ok && fitsIn(limit, to) {
			return findings.Finding{}, false
		}
	}

	pos := s.fset.Position(call.Pos())
	return findings.Finding{
		RuleID:     ruleID,
		Severity:   findings.SeverityMedium,
		Confidence: findings.ConfidenceMedium,
		Message: "Integer conversion " + typeName(from) + " to " + typeName(to) +
			" (" + reason + ") sizes an allocation or slice bound " + how + " without a range check",
		Location: findings.Location{
			FilePath:    s.path,
			StartLine:   pos.Line,
			EndLine:     pos.Line,
			StartColumn: pos.Column,
		},
		Metadata: map[string]string{
			"cwe":  "CWE-190",
			"from": typeName(from),
			"to":   typeName(to),
		},
	}, true
}

// plainNames returns the bare identifiers an expression is built from, so a
// guard on any of them suppresses the conversion.
func plainNames(e ast.Expr) []string {
	var out []string
	ast.Inspect(e, func(n ast.Node) bool {
		// Only identifiers in value position: a selector's field name is not a
		// name this analyzer tracks.
		switch v := n.(type) {
		case *ast.SelectorExpr:
			return false
		case *ast.Ident:
			out = append(out, v.Name)
		}
		return true
	})
	return out
}

// typeName renders a kind back to the canonical Go type name, for messages.
func typeName(k intKind) string {
	if k.signed {
		switch k.bits {
		case 8:
			return "int8"
		case 16:
			return "int16"
		case 32:
			return "int32"
		}
		return "int64"
	}
	switch k.bits {
	case 8:
		return "uint8"
	case 16:
		return "uint16"
	case 32:
		return "uint32"
	}
	return "uint64"
}

func unparen(e ast.Expr) ast.Expr {
	for {
		p, ok := e.(*ast.ParenExpr)
		if !ok {
			return e
		}
		e = p.X
	}
}

// ---------------------------------------------------------------------------
// File filters
// ---------------------------------------------------------------------------

// isTestPath reports whether a path is Go test code or a test fixture tree.
