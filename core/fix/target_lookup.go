package fix

import (
	"context"
	"sync"
)

// maxTargetLookups bounds how many target searches ask the Checker at once.
// Each search is a chain of dependent questions, but searches for different
// packages are independent, and asking them one after another makes the wait
// the sum of every round trip.
const maxTargetLookups = 8

// targetQuery is one target search. Two manifest directories on the same
// installed version with the same named fix ask the same question and share
// its answer.
type targetQuery struct {
	ecosystem, pkg, from, initial string
}

// resolveTargets answers every distinct query, at most maxTargetLookups at a
// time, through one memo so no (ecosystem, package, version) is asked twice in
// a plan. A monorepo pins the same packages in hundreds of lockfiles; asking
// once per directory sent llama_index's assessment 9,856 sequential requests
// for 139 distinct versions.
func resolveTargets(ctx context.Context, c Checker, queries []targetQuery) map[targetQuery]resolution {
	out := make(map[targetQuery]resolution, len(queries))
	if c == nil {
		for _, q := range queries {
			out[q] = resolution{Target: q.initial}
		}
		return out
	}
	memo := newMemoChecker(c)
	var (
		mu   sync.Mutex
		wg   sync.WaitGroup
		slot = make(chan struct{}, maxTargetLookups)
	)
	for _, q := range queries {
		mu.Lock()
		_, dup := out[q]
		if !dup {
			out[q] = resolution{} // reserved; filled below
		}
		mu.Unlock()
		if dup {
			continue
		}
		wg.Add(1)
		slot <- struct{}{}
		go func(q targetQuery) {
			defer func() { <-slot; wg.Done() }()
			res := resolveTarget(ctx, memo, q.ecosystem, q.pkg, q.from, q.initial)
			mu.Lock()
			out[q] = res
			mu.Unlock()
		}(q)
	}
	wg.Wait()
	return out
}

// Memoize returns a Checker that asks c each (ecosystem, package, version)
// once, for callers that plan more than once over the same scan (fix_plan
// plans directly and again through the assessment). Nil stays nil, so an
// offline plan stays offline.
func Memoize(c Checker) Checker {
	if c == nil {
		return nil
	}
	return newMemoChecker(c)
}

// memoChecker asks each (ecosystem, package, version) once. Concurrent askers
// of the same key wait for the first answer, error included, so every search
// in a plan sees the same answer for the same version.
type memoChecker struct {
	inner Checker
	mu    sync.Mutex
	calls map[string]*memoCall
}

type memoCall struct {
	done chan struct{}
	rem  []Residual
	err  error
}

func newMemoChecker(c Checker) *memoChecker {
	return &memoChecker{inner: c, calls: map[string]*memoCall{}}
}

func (m *memoChecker) Remaining(ctx context.Context, ecosystem, pkg, version string) ([]Residual, error) {
	key := ecosystem + "\x00" + pkg + "\x00" + version
	m.mu.Lock()
	call, ok := m.calls[key]
	if !ok {
		call = &memoCall{done: make(chan struct{})}
		m.calls[key] = call
	}
	m.mu.Unlock()
	if !ok {
		call.rem, call.err = m.inner.Remaining(ctx, ecosystem, pkg, version)
		close(call.done)
	}
	select {
	case <-call.done:
		return call.rem, call.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
