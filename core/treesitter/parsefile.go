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
	// ReasonDeadline means the parse did not finish within its deadline.
	ReasonDeadline Reason = "deadline"
	// ReasonMemory means the record array outgrew the guest's memory, on a fresh
	// instance.
	ReasonMemory Reason = "memory"
	// ReasonTrap means the guest trapped, on a fresh instance: an assertion, an
	// out-of-bounds access, or an allocation inside the tree-sitter runtime
	// failing (the runtime aborts on that, which arrives as a trap).
	ReasonTrap Reason = "trap"
	// ReasonErrorTree means the parse needed error recovery; the tree is returned
	// but not trusted.
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
	// Deadline is Base plus PerMiB for each MiB of source.
	Base, PerMiB time.Duration
}

// DefaultBudget declines files over 2 MiB (minified bundles and generated
// tables, where a parse is slow and a tree tells the analyzers little) and
// gives a parse 5 s plus 5 s per MiB, far above the measured 0.5–1 MB/s on a
// loaded machine: the deadline is a backstop for a pathological file, not a
// budget a normal one gets near.
var DefaultBudget = Budget{MaxBytes: 2 << 20, Base: 5 * time.Second, PerMiB: 5 * time.Second}

func (b Budget) orDefault() Budget {
	if b == (Budget{}) {
		return DefaultBudget
	}
	return b
}

// ParseFile parses src as lang within budget. It returns a tree, or a
// Limitation saying why there is no usable one; on ReasonErrorTree the tree is
// returned too, for a caller that wants to look. It never returns a bare
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
	if p.onDeadlineStart != nil {
		p.onDeadlineStart(module)
	}
	pctx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()
	tree, err := p.Parse(pctx, lang, src)
	switch {
	case err == nil && tree.HasError():
		return tree, &Limitation{Reason: ReasonErrorTree, Detail: "the parse needed error recovery"}
	case err == nil:
		return tree, nil
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
