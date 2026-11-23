package treesitter

import (
	"context"
	"math/rand"
	"strings"
	"testing"
	"time"
)

// The work budget is decided by the source alone: a parse that takes c checks
// is admitted by a budget of c and declined by c-1, on a reused instance and
// on a fresh one alike, and a declined parse leaves the parser usable.
func TestParseFileWorkBudgetIsExact(t *testing.T) {
	p := newParser(t)
	ctx := context.Background()
	src := []byte(strings.Repeat("a < b > c ? d : ", 3000))
	tree, err := p.Parse(ctx, "java", src)
	if err != nil {
		t.Fatal(err)
	}
	c := tree.Checks
	if c < 10 {
		t.Fatalf("the source took %d checks; too few to bound", c)
	}
	for _, fresh := range []bool{false, true} {
		q := p
		if fresh {
			q = newParser(t)
		}
		if _, lim := q.ParseFile(ctx, "java", src, Budget{MaxBytes: 1 << 30, Checks: c, Base: time.Hour}); lim != nil && lim.Reason != ReasonErrorTree {
			t.Errorf("fresh=%v: a budget of %d checks declined a parse that takes %d: %v", fresh, c, c, lim)
		}
		_, lim := q.ParseFile(ctx, "java", src, Budget{MaxBytes: 1 << 30, Checks: c - 1, Base: time.Hour})
		if lim == nil || lim.Reason != ReasonBudget {
			t.Errorf("fresh=%v: a budget of %d checks for a parse that takes %d gave %v, want ReasonBudget", fresh, c-1, c, lim)
		}
	}
	if tree, lim := p.ParseFile(ctx, "python", []byte("x = 1\n"), Budget{}); lim != nil || tree == nil {
		t.Fatalf("after a spent budget the next parse got %v", lim)
	}
}

// The checks a parse takes depend on the source, not on what else the
// machine is doing: the same file takes the same count while other parses run.
func TestParseChecksDoNotDependOnLoad(t *testing.T) {
	p := newParser(t)
	ctx := context.Background()
	src := []byte(strings.Repeat("def f(x):\n    return g(x, [y for y in x if y])\n", 400))
	quiet, err := p.Parse(ctx, "python", src)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	errs := make(chan error, 8)
	for range 8 {
		go func() {
			for {
				select {
				case <-done:
					errs <- nil
					return
				default:
				}
				if _, err := p.Parse(ctx, "javascript", src); err != nil {
					errs <- err
					return
				}
			}
		}()
	}
	for range 5 {
		busy, err := p.Parse(ctx, "python", src)
		if err != nil {
			t.Fatal(err)
		}
		if busy.Checks != quiet.Checks {
			t.Errorf("under load the parse took %d checks, alone %d", busy.Checks, quiet.Checks)
		}
	}
	close(done)
	for range 8 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
}

// DefaultBudget admits ordinary source with room to spare and stops a
// pathological one. The measured corpus maximum is 27.6 checks per KiB (see
// DefaultBudget); these sources stand for it in a test.
func TestDefaultBudget(t *testing.T) {
	p := newParser(t)
	ctx := context.Background()
	ordinary := []struct{ lang, src string }{
		{"python", strings.Repeat("def f(x):\n    return g(x, [y for y in x if y])\n", 2000)},
		{"java", strings.Repeat("class A { int g(int x) { return x > 0 ? f(x - 1) : 0; } }\n", 1500)},
		{"javascript", strings.Repeat("const h = (a, b) => a.map(x => ({ k: x, v: `${b}` }));\n", 1500)},
		{"typescript", strings.Repeat("export function h(n: number): Array<string> { return [String(n)]; }\n", 1500)},
	}
	for _, o := range ordinary {
		if _, lim := p.ParseFile(ctx, o.lang, []byte(o.src), Budget{}); lim != nil {
			t.Errorf("%s: DefaultBudget declined ordinary source: %v", o.lang, lim)
		}
		tree, err := p.Parse(ctx, o.lang, []byte(o.src))
		if err != nil {
			t.Fatal(err)
		}
		if perKiB := float64(tree.Checks) / (float64(len(o.src)) / 1024); perKiB > float64(DefaultBudget.ChecksPerKiB)/2 {
			t.Errorf("%s: %.1f checks per KiB, over half the budget's %d", o.lang, perKiB, DefaultBudget.ChecksPerKiB)
		}
	}
}

// A parse whose every version is recovering from an error stops there, as an
// error tree, rather than spending the work budget on recovery: these 300 KB
// of random bytes read as JavaScript took over 50 s before. Parse, which sets no
// bounds, still finishes it, and its tree has the error: the stop never
// falls on a parse that would come out clean.
func TestParseFileStopsAtCertainError(t *testing.T) {
	p := newParser(t)
	ctx := context.Background()
	junk := make([]byte, 300_000)
	r := rand.New(rand.NewSource(1))
	for i := range junk {
		junk[i] = byte(1 + r.Intn(255))
	}
	start := time.Now()
	tree, lim := p.ParseFile(ctx, "javascript", junk, Budget{})
	if lim == nil || lim.Reason != ReasonErrorTree || tree != nil {
		t.Fatalf("tree=%v limitation=%v, want no tree and ReasonErrorTree", tree != nil, lim)
	}
	if el := time.Since(start); el > 5*time.Second {
		t.Errorf("the stop took %v; it should come within the first checks", el)
	}
	full, err := p.Parse(ctx, "javascript", junk[:16<<10])
	if err != nil {
		t.Fatal(err)
	}
	if !full.HasError() {
		t.Error("the unbounded parse of the same bytes has no error; the stop would have dropped a clean tree")
	}
	// Source with a local error keeps its versions out of recovery, and its
	// tree comes back for a caller that wants to look.
	if tree, lim := p.ParseFile(ctx, "python", []byte("def f(:\n    return 1\n"), Budget{}); lim == nil || lim.Reason != ReasonErrorTree || tree == nil {
		t.Errorf("tree=%v limitation=%v, want the tree and ReasonErrorTree", tree != nil, lim)
	}
}
