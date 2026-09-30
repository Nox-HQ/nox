// Package parallel runs independent per-item work on every core while keeping
// the result exactly what a sequential loop would produce.
//
// Analyzers used to walk their files one at a time. They run concurrently with
// each other, but the slowest one (secrets, on most repositories) then held the
// whole scan on a single core for most of its duration. Map spreads one
// analyzer's files across the cores and hands results back in input order, so
// findings, their order and every error are the same as the loop it replaces.
package parallel

import (
	"context"
	"runtime"
	"sync"
	"sync/atomic"
)

// Map calls fn(i) for every i in [0, n) on up to GOMAXPROCS goroutines and
// returns the results indexed by i. If any call fails, Map returns the error of
// the LOWEST failing index — the one a sequential loop would have stopped at —
// so the reported error does not depend on scheduling. Cancelling ctx stops
// items not yet started and returns ctx's error.
func Map[T any](ctx context.Context, n int, fn func(i int) (T, error)) ([]T, error) {
	out := make([]T, n)
	if n == 0 {
		return out, ctx.Err()
	}
	workers := min(runtime.GOMAXPROCS(0), n)
	errs := make([]error, n)
	var next atomic.Int64
	// firstFail is the lowest index known to have failed (n while none has).
	var firstFail atomic.Int64
	firstFail.Store(int64(n))
	fail := func(i int, err error) {
		errs[i] = err
		for {
			cur := firstFail.Load()
			if int64(i) >= cur || firstFail.CompareAndSwap(cur, int64(i)) {
				return
			}
		}
	}
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i := int(next.Add(1) - 1)
				if i >= n {
					return
				}
				// Skip only items AFTER a known failure: a sequential loop
				// would never have reached them. Anything before it still
				// runs, so the lowest failing index is the one reported.
				if int64(i) > firstFail.Load() {
					continue
				}
				if err := ctx.Err(); err != nil {
					fail(i, err)
					continue
				}
				v, err := fn(i)
				if err != nil {
					fail(i, err)
					continue
				}
				out[i] = v
			}
		}()
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}
