package fix

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nox-hq/nox/core/findings"
)

// countingChecker records every question and how many were in flight at once.
type countingChecker struct {
	answers  map[string][]Residual
	delay    time.Duration
	mu       sync.Mutex
	asked    map[string]int
	inFlight atomic.Int32
	peak     atomic.Int32
}

func newCountingChecker(answers map[string][]Residual, delay time.Duration) *countingChecker {
	return &countingChecker{answers: answers, delay: delay, asked: map[string]int{}}
}

func (c *countingChecker) Remaining(ctx context.Context, eco, pkg, v string) ([]Residual, error) {
	n := c.inFlight.Add(1)
	defer c.inFlight.Add(-1)
	for {
		p := c.peak.Load()
		if n <= p || c.peak.CompareAndSwap(p, n) {
			break
		}
	}
	c.mu.Lock()
	c.asked[eco+"/"+pkg+"@"+v]++
	c.mu.Unlock()
	select {
	case <-time.After(c.delay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return c.answers[pkg+"@"+v], nil
}

func vulnIn(dir, eco, pkg, from, fixed string) findings.Finding {
	f := vuln(eco, pkg, from, fixed)
	f.Location.FilePath = dir + "/package-lock.json"
	return f
}

// Counterexample from llama_index: ~600 lockfiles pin the same packages, and
// the assessment asked OSV once per (directory, package) — 9,856 sequential
// calls for 139 distinct versions, 47 minutes after the reports were written.
// One plan asks each (ecosystem, package, version) once.
func TestPlanAsksEachVersionOnceAcrossDirectories(t *testing.T) {
	var items []findings.Finding
	for d := 0; d < 200; d++ {
		items = append(items, vulnIn(fmt.Sprintf("pkg%03d", d), "npm", "axios", "0.21.1", "0.33.0"))
	}
	c := newCountingChecker(map[string][]Residual{
		"axios@0.33.0": {{ID: "GHSA-9fr6", FixedIn: "0.34.0"}},
	}, 0)
	plan := PlanUpgrades(items, Options{Checker: c})

	if len(plan.Actions) != 200 {
		t.Fatalf("want one action per directory, got %d", len(plan.Actions))
	}
	for _, a := range plan.Actions {
		if a.To != "0.34.0" || a.Unverified {
			t.Fatalf("every directory gets the resolved target: %+v", a)
		}
	}
	for q, n := range c.asked {
		if n != 1 {
			t.Errorf("%s asked %d times, want 1", q, n)
		}
	}
	if len(c.asked) != 2 {
		t.Errorf("want 2 distinct questions (0.33.0, 0.34.0), got %v", c.asked)
	}
}

// Distinct packages are independent questions; asking them one after another
// makes the wait the sum of every round trip.
func TestPlanResolvesDistinctPackagesConcurrently(t *testing.T) {
	var items []findings.Finding
	for p := 0; p < 32; p++ {
		items = append(items, vuln("npm", fmt.Sprintf("p%02d", p), "1.0.0", "1.0.1"))
	}
	c := newCountingChecker(nil, 20*time.Millisecond)
	PlanUpgrades(items, Options{Checker: c})

	if peak := c.peak.Load(); peak < 2 || peak > maxTargetLookups {
		t.Errorf("peak concurrent lookups %d, want 2..%d", peak, maxTargetLookups)
	}
}

// Concurrency must not change the plan: actions stay in discovery order and
// match the sequential answer.
func TestPlanOrderIsDiscoveryOrderUnderConcurrency(t *testing.T) {
	var items []findings.Finding
	for p := 0; p < 40; p++ {
		items = append(items, vuln("npm", fmt.Sprintf("p%02d", p), "1.0.0", "1.0.1"))
	}
	c := newCountingChecker(map[string][]Residual{
		"p07@1.0.1": {{ID: "X", FixedIn: "1.0.2"}},
	}, time.Millisecond)
	plan := PlanUpgrades(items, Options{Checker: c})

	for i, a := range plan.Actions {
		if want := fmt.Sprintf("p%02d", i); a.Package != want {
			t.Fatalf("action %d is %s, want %s", i, a.Package, want)
		}
	}
	if plan.Actions[7].To != "1.0.2" {
		t.Errorf("p07 follows its residual to 1.0.2, got %s", plan.Actions[7].To)
	}
}

// A caller that cannot wait gets an answer, not a hang: targets the source did
// not confirm in time are Unverified, never reported as clearing everything.
func TestPlanContextBoundsTheWaitAndMarksUnverified(t *testing.T) {
	items := []findings.Finding{vuln("npm", "axios", "0.21.1", "0.33.0")}
	c := newCountingChecker(nil, time.Hour)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	plan := PlanUpgradesContext(ctx, items, Options{Checker: c})
	if el := time.Since(start); el > 5*time.Second {
		t.Fatalf("plan waited %s past its deadline", el)
	}
	if len(plan.Actions) != 1 || !plan.Actions[0].Unverified || plan.Actions[0].To != "0.33.0" {
		t.Fatalf("an unanswered target is the findings' own fix, marked Unverified: %+v", plan.Actions)
	}
}
