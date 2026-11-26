package treesitter

import (
	"context"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

var hostSources = []struct{ lang, src string }{
	{"python", "def f(x):\n    return x + 1\n"},
	{"java", "class A { int g() { return 1; } }\n"},
	{"python", strings.Repeat("v = call(a, b, c)\n", 2000)},
	{"typescript", "export function h(n: number): number { return n * 2; }\n"},
	{"python", "def f(:\n"},
	{"tsx", "const X = () => <a href={u}>{t}</a>;\n"},
	{"python", "def f(x):\n    return x + 1\n"},
	{"csharp", "class A { int G() { return 1; } }\n"},
	{"php", "<?php\nfunction g() { return 1; }\n"},
	{"ruby", "def g\n  1\nend\n"},
	{"kotlin", "class A { fun g(): Int { return 1 } }\n"},
}

// A pooled instance answers exactly as a fresh one: the same sequence of
// files, parsed on one parser (instances reused) and each on a new parser
// (always fresh), gives identical trees.
func TestReusedInstancesAnswerAsFreshOnes(t *testing.T) {
	ctx := context.Background()
	shared := newParser(t)
	for i, c := range hostSources {
		got, err := shared.Parse(ctx, c.lang, []byte(c.src))
		if err != nil {
			t.Fatalf("source %d: %v", i, err)
		}
		fresh := newParser(t)
		want, err := fresh.Parse(ctx, c.lang, []byte(c.src))
		if err != nil {
			t.Fatalf("source %d, fresh: %v", i, err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("source %d (%s): the reused instance's tree differs from a fresh instance's", i, c.lang)
		}
	}
	shared.mu.Lock()
	pooled := len(shared.idle["python"])
	shared.mu.Unlock()
	if pooled == 0 {
		t.Error("no python instance was pooled: the test did not exercise reuse")
	}
}

func TestConcurrentParsesAgree(t *testing.T) {
	ctx := context.Background()
	p := newParser(t)
	want := make([]*Tree, len(hostSources))
	for i, c := range hostSources {
		tr, err := p.Parse(ctx, c.lang, []byte(c.src))
		if err != nil {
			t.Fatal(err)
		}
		want[i] = tr
	}
	var wg sync.WaitGroup
	errs := make(chan string, 64)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i, c := range hostSources {
				tr, err := p.Parse(ctx, c.lang, []byte(c.src))
				if err != nil || !reflect.DeepEqual(tr, want[i]) {
					errs <- c.lang
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for l := range errs {
		t.Errorf("a concurrent %s parse differed or failed", l)
	}
}

func TestParseFileDeclinesAFileOverBudget(t *testing.T) {
	p := newParser(t)
	tree, lim := p.ParseFile(context.Background(), "python", make([]byte, 101), Budget{MaxBytes: 100, Base: time.Minute})
	if tree != nil || lim == nil || lim.Reason != ReasonTooLarge {
		t.Fatalf("tree=%v limitation=%v, want ReasonTooLarge", tree != nil, lim)
	}
	atBudget := []byte("#" + strings.Repeat("a", 98) + "\n") // a valid 100-byte source
	if _, lim := p.ParseFile(context.Background(), "python", atBudget, Budget{MaxBytes: 100, Base: time.Minute}); lim != nil {
		t.Errorf("a file at the budget was declined: %v", lim)
	}
}

// A parse that misses its deadline is a limitation, and the parser is still
// usable: the instance it ran on is closed, not pooled.
func TestParseFileDeadlineIsALimitationNotAPoisonedPool(t *testing.T) {
	p := newParser(t)
	ctx := context.Background()
	src := []byte(strings.Repeat("v = call(a, b, c)\n", 20000))
	_, lim := p.ParseFile(ctx, "python", src, Budget{MaxBytes: 1 << 30, Base: time.Nanosecond})
	if lim == nil || lim.Reason != ReasonDeadline {
		t.Fatalf("limitation %v, want ReasonDeadline", lim)
	}
	tree, lim := p.ParseFile(ctx, "python", []byte("x = 1\n"), Budget{})
	if lim != nil || tree == nil {
		t.Fatalf("the next parse got %v; a missed deadline left the parser unusable", lim)
	}
}

func TestParseFileErrorTreeIsReturnedAndFlagged(t *testing.T) {
	p := newParser(t)
	tree, lim := p.ParseFile(context.Background(), "python", []byte("def f(:\n"), Budget{})
	if lim == nil || lim.Reason != ReasonErrorTree || tree == nil {
		t.Fatalf("tree=%v limitation=%v, want the tree and ReasonErrorTree", tree != nil, lim)
	}
}

func TestParseFileUnknownLanguage(t *testing.T) {
	p := newParser(t)
	if _, lim := p.ParseFile(context.Background(), "cobol", []byte("x"), Budget{}); lim == nil || lim.Reason != ReasonLanguage {
		t.Errorf("limitation %v, want ReasonLanguage", lim)
	}
}

// Out of memory is classified, and it is the fresh instance's answer: the
// failing instance is never pooled, and the retry runs on a new one.
func TestParseFileOutOfMemoryIsClassified(t *testing.T) {
	ctx := context.Background()
	// 40 pages (2.5 MiB): enough to instantiate the python module and parse a
	// small file, not enough for this one's records.
	p, err := newParserWithLimit(ctx, 40)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close(ctx) })
	if _, lim := p.ParseFile(ctx, "python", []byte("x = 1\n"), Budget{}); lim != nil {
		t.Fatalf("a small file failed under the limit: %v", lim)
	}
	_, lim := p.ParseFile(ctx, "python", []byte(strings.Repeat("v = call(a, b, c)\n", 20000)), Budget{})
	if lim == nil || (lim.Reason != ReasonMemory && lim.Reason != ReasonTrap) {
		t.Fatalf("limitation %v, want ReasonMemory or ReasonTrap", lim)
	}
	p.mu.Lock()
	idle := len(p.idle["python"])
	p.mu.Unlock()
	if idle != 0 {
		t.Errorf("%d instance(s) pooled after both the reused and the fresh instance failed; a failed instance must be closed", idle)
	}
	if _, lim := p.ParseFile(ctx, "python", []byte("x = 1\n"), Budget{}); lim != nil {
		t.Errorf("after running out of memory, a small file failed: %v", lim)
	}
}

// A reused instance whose heap an earlier parse filled fails where a fresh
// one succeeds; Parse must return the fresh instance's answer, so the result
// does not depend on what the instance parsed before.
func TestAFailureOnAReusedInstanceIsRetriedFresh(t *testing.T) {
	ctx := context.Background()
	p, err := newParserWithLimit(ctx, 40) // 2.5 MiB
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close(ctx) })
	src := []byte(strings.Repeat("v = call(a, b)\n", 200))
	if _, err := p.Parse(ctx, "python", src); err != nil {
		t.Fatalf("a fresh instance could not parse the file: %v", err)
	}
	// Fill the pooled instance's heap, as a large earlier file might have.
	p.mu.Lock()
	inst := p.idle["python"][0]
	p.mu.Unlock()
	g := guest{ctx: ctx, m: inst.m}
	filled := 0
	for g.call("nox_alloc", 64<<10) != 0 && g.err == nil {
		filled++
	}
	if filled == 0 {
		t.Fatal("could not fill the instance's heap; the test would not exercise the retry")
	}
	if _, err := p.Parse(ctx, "python", src); err != nil {
		t.Errorf("Parse failed on the filled instance and did not retry on a fresh one: %v", err)
	}
}

// The first parse of a language compiles its module; that is not the file's
// parse and must not count against its deadline. Checked by order, not by
// timing: when the deadline starts, the module is already compiled.
func TestParseFileDeadlineExcludesCompilation(t *testing.T) {
	p := newParser(t) // nothing compiled yet
	starts := 0
	p.onDeadlineStart = func(module string) {
		starts++
		p.mu.Lock()
		_, compiled := p.compiled[module]
		p.mu.Unlock()
		if !compiled {
			t.Errorf("the deadline for a %s parse started before its module was compiled", module)
		}
	}
	if _, lim := p.ParseFile(context.Background(), "python", []byte("x = 1\n"), Budget{}); lim != nil {
		t.Fatal(lim)
	}
	if starts != 1 {
		t.Fatalf("the deadline hook ran %d times", starts)
	}
}
