package treesitter

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Reason says why a file's tree cannot be used. A front end that gets one
// falls back to the line recognizer for that file (ADR 0006, rule 3) and
// records the reason as a limitation of the file, never as a failed scan.
type Reason string

const (
	// ReasonTooLarge means the file is over Budget.MaxBytes and was not parsed. The
	// one decline decided before any work, so the same file always gets it.
	ReasonTooLarge Reason = "too-large"
	// ReasonBudget means the parse needed more work than its budget allows:
	// more parser operations than Budget.Checks gives the file. Work is
	// counted, not timed, so the same file gets it on every machine.
	ReasonBudget Reason = "budget"
	// ReasonDeadline means the parse did not finish within its wall-clock
	// backstop, or the scan was cancelled. The one reason that depends on the
	// machine: the backstop sits far above any parse the work budget admits,
	// for a runtime defect that stops counting work.
	ReasonDeadline Reason = "deadline"
	// ReasonMemory means the record array outgrew the guest's memory, on a fresh
	// instance.
	ReasonMemory Reason = "memory"
	// ReasonTrap means the guest trapped, on a fresh instance: an assertion, an
	// out-of-bounds access, or an allocation inside the tree-sitter runtime
	// failing (the runtime aborts on that, which arrives as a trap).
	ReasonTrap Reason = "trap"
	// ReasonErrorTree means the parse needed error recovery, and its tree is
	// not trusted. ParseFile stops a parse as soon as every version of it is
	// recovering (the error is then certain), so usually no tree comes back;
	// one that recovered between two progress checks is returned for a caller
	// that wants to look.
	ReasonErrorTree Reason = "error-tree"
	// ReasonLanguage means no embedded grammar parses this language.
	ReasonLanguage Reason = "language"
)

// Limitation is a reason and what produced it.
type Limitation struct {
	Reason Reason
	Detail string
}

func (l *Limitation) Error() string { return "treesitter: " + string(l.Reason) + ": " + l.Detail }

// Budget bounds one parse. The zero value is DefaultBudget.
type Budget struct {
	// MaxBytes declines a larger file as ReasonTooLarge.
	MaxBytes int
	// The work budget, in progress checks (one per 100 parser operations):
	// Checks plus ChecksPerKiB for each KiB of source. Over it, the parse stops
	// with ReasonBudget. 0 and 0 set no bound.
	Checks, ChecksPerKiB uint32
	// The wall-clock backstop: Base plus PerMiB for each MiB of source.
	Base, PerMiB time.Duration
}

// DefaultBudget declines files over 2 MiB (minified bundles and generated
// tables, where a parse is slow and a tree tells the analyzers little).
//
// The work budget is what decides a pathological file, and it is counted, not
// timed, so a file parses or falls back the same way on every machine at any
// load. Before, a 5 s deadline decided it, and under a load average above 100
// a normal file missed it, fell back to the line reader and changed the
// scan's findings.
//
// Measured on the RealVuln corpus (44,857 Python, JavaScript, TypeScript, TSX
// and Java files, vendored and minified ones included): the costliest took
// 27.6 checks per KiB, and no file under 4 KiB more than 75. The budget,
// 2,000 checks plus 64 per KiB, admits every one with 2.3 times the
// costliest's ratio. Two runs of the corpus, at different load, counted the
// same checks for every file.
//
// Checks bound work, not time: in error recovery one check costs ten times
// what it costs in source: 300 KB of bytes that are not source, read as
// JavaScript, took 30 to over 50 s inside a budget of their size. ParseFile stops
// such a parse when every version of it is recovering, which makes its tree
// an error tree the caller would not use; on the corpus that stop never fell
// on a parse whose tree came out clean, and the 300 KB took 5 to 13 ms.
//
// The wall-clock backstop is only for a runtime defect that stops counting
// work, and sits far above anything the work budget lets run.
var DefaultBudget = Budget{
	MaxBytes: 2 << 20,
	Checks:   2000, ChecksPerKiB: 64,
	Base: time.Minute, PerMiB: time.Minute,
}

func (b Budget) orDefault() Budget {
	if b == (Budget{}) {
		return DefaultBudget
	}
	return b
}

// ParseFile parses src as lang within budget. It returns a tree, or a
// Limitation saying why there is no usable one; on ReasonErrorTree the tree
// may be returned too (see ReasonErrorTree). It never returns a bare
// error: every failure is classified, because the caller's only choices are
// "use the tree" and "fall back and record why".
func (p *Parser) ParseFile(ctx context.Context, lang string, src []byte, budget Budget) (*Tree, *Limitation) {
	budget = budget.orDefault()
	module, ok := moduleOf[lang]
	if !ok {
		return nil, &Limitation{Reason: ReasonLanguage, Detail: lang}
	}
	if len(src) > budget.MaxBytes {
		return nil, &Limitation{Reason: ReasonTooLarge, Detail: fmt.Sprintf("%d bytes, budget %d", len(src), budget.MaxBytes)}
	}
	// Compile before the deadline starts: the first file of a language would
	// otherwise pay for compiling the module, seconds on a loaded machine, and
	// miss a deadline no later file would.
	if _, err := p.compiledModule(ctx, module); err != nil {
		return nil, &Limitation{Reason: ReasonLanguage, Detail: err.Error()}
	}
	deadline := budget.Base + time.Duration(float64(budget.PerMiB)*float64(len(src))/(1<<20))
	checks := budget.maxChecks(len(src))
	if p.onDeadlineStart != nil {
		p.onDeadlineStart(module)
	}
	pctx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()
	tree, err := p.parse(pctx, lang, src, bounds{maxChecks: checks, stopAtError: true})
	switch {
	case err == nil && tree.HasError():
		return tree, &Limitation{Reason: ReasonErrorTree, Detail: "the parse needed error recovery"}
	case err == nil:
		return tree, nil
	case errors.Is(err, ErrRecovery):
		return nil, &Limitation{Reason: ReasonErrorTree, Detail: "the parse could not avoid error recovery"}
	case errors.Is(err, ErrBudget):
		return nil, &Limitation{Reason: ReasonBudget, Detail: fmt.Sprintf("more than %d progress checks for %d bytes", checks, len(src))}
	case errors.Is(pctx.Err(), context.DeadlineExceeded) && ctx.Err() == nil:
		return nil, &Limitation{Reason: ReasonDeadline, Detail: fmt.Sprintf("not done within %v", deadline)}
	case ctx.Err() != nil:
		return nil, &Limitation{Reason: ReasonDeadline, Detail: "the scan was cancelled: " + ctx.Err().Error()}
	case errors.Is(err, ErrLanguage):
		return nil, &Limitation{Reason: ReasonLanguage, Detail: err.Error()}
	case errors.Is(err, ErrMemory):
		return nil, &Limitation{Reason: ReasonMemory, Detail: err.Error()}
	default:
		return nil, &Limitation{Reason: ReasonTrap, Detail: err.Error()}
	}
}

// maxChecks is the work budget for n bytes of source, 0 for none.
func (b Budget) maxChecks(n int) uint32 {
	if b.Checks == 0 && b.ChecksPerKiB == 0 {
		return 0
	}
	c := uint64(b.Checks) + uint64(b.ChecksPerKiB)*uint64(n)/1024
	if c > 1<<32-1 {
		c = 1<<32 - 1
	}
	return uint32(c)
}
