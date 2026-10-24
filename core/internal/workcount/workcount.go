// Package workcount counts units of work that a test needs to see grow with
// its input, where the clock cannot be trusted to show it.
//
// A file's secrets scan must cost time linear in its findings (#827). A test
// that decided this by wall-clock ratio flaked under machine load and on slow
// CI runners, because elapsed time on a shared machine is not the work done.
// The operations that went quadratic -- walking a file from byte 0 per
// finding, re-lexing it per finding, searching it to EOF per finding,
// comparing every finding with every other -- report what they walked or
// compared here instead, and the test asserts on those counts, which are the
// same on every machine.
//
// Counting is off unless a test turns it on, and Add is then one atomic load.
// Callers add once per call or per loop, never per byte, so the hook costs
// nothing measurable on the paths it watches.
package workcount

import "sync/atomic"

// Kind names one operation whose cost must stay linear in a file's size.
type Kind int

const (
	// OffsetWalk is bytes walked to convert between a (line, column) and a
	// byte offset, plus one per lookup answered from a pinned index.
	OffsetWalk Kind = iota
	// Lex is bytes lexically classified.
	Lex
	// DataURISearch is bytes searched for a data: URI scheme.
	DataURISearch
	// DedupVisit is findings visited while deduplicating a file's findings:
	// one per candidate an anchor is compared with.
	DedupVisit
	numKinds
)

var (
	enabled atomic.Bool
	counts  [numKinds]atomic.Int64
)

// Add records n units of work of kind k when counting is on.
func Add(k Kind, n int) {
	if enabled.Load() {
		counts[k].Add(int64(n))
	}
}

// Counts is the work recorded, indexed by Kind.
type Counts [numKinds]int64

// Start zeroes the counters and turns counting on; stop turns it off and
// returns what was recorded. The counters are process-wide: count one scan
// at a time, from a test that is not parallel.
func Start() (stop func() Counts) {
	for i := range counts {
		counts[i].Store(0)
	}
	enabled.Store(true)
	return func() Counts {
		enabled.Store(false)
		var c Counts
		for i := range counts {
			c[i] = counts[i].Load()
		}
		return c
	}
}

// Kinds lists every kind, in order.
func Kinds() []Kind {
	ks := make([]Kind, numKinds)
	for i := range ks {
		ks[i] = Kind(i)
	}
	return ks
}

func (k Kind) String() string {
	switch k {
	case OffsetWalk:
		return "offset-walk bytes"
	case Lex:
		return "lexed bytes"
	case DataURISearch:
		return "data: URI search bytes"
	case DedupVisit:
		return "dedup visits"
	}
	return "unknown"
}
