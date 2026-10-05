package lexctx

import (
	"sort"
	"sync"
	"unsafe"
)

// Pin makes LineColToOffset, LineForOffset and Classify answer for exactly
// this content slice from a per-file index, until release is called.
//
// The helpers above take the whole file and walk it from the start, and an
// analyzer calls them once or more per finding: the secrets pipeline did so
// from dedup and eight refiners, so a file's cost grew with findings x file
// size. 7,139 JWTs in a 1 MB Python file took 39 s, 77% of it in
// LineColToOffset; a repository can be written to look like that. Threading
// an index through every helper's signature would touch every caller; pinning
// the content for the duration of one file's scan lets every caller, in this
// package and others, benefit unchanged.
//
// A call is served from the index only when its slice is the pinned one --
// the same backing array AND the same length. Any other slice (a subslice, a
// copy, another file) takes the ordinary path, so the answer is the function's
// definition in every case; the index merely computes it faster. The pinned
// bytes must not be modified until release; release must be called (defer it)
// so the content can be freed.
func Pin(content []byte) (release func()) {
	if len(content) == 0 {
		return func() {}
	}
	k := keyOf(content)
	p := &pinned{content: content}
	pins.Store(k, p)
	return func() { pins.CompareAndDelete(k, p) }
}

type pinKey struct {
	data unsafe.Pointer
	n    int
}

type pinned struct {
	content []byte

	once   sync.Once
	starts []int // starts[i] is the offset of line i+1

	mu      sync.Mutex
	regions map[Lang][]Region
}

var pins sync.Map // pinKey -> *pinned

func keyOf(content []byte) pinKey {
	return pinKey{unsafe.Pointer(unsafe.SliceData(content)), len(content)}
}

// pinnedFor returns the pin for exactly this slice, or nil.
func pinnedFor(content []byte) *pinned {
	if len(content) == 0 {
		return nil
	}
	v, ok := pins.Load(keyOf(content))
	if !ok {
		return nil
	}
	return v.(*pinned)
}

func (p *pinned) lineStarts() []int {
	p.once.Do(func() {
		starts := []int{0}
		for i, c := range p.content {
			if c == '\n' {
				starts = append(starts, i+1)
			}
		}
		p.starts = starts
	})
	return p.starts
}

// offset is LineColToOffset's definition, answered from the line index.
func (p *pinned) offset(line, col int) int {
	if line < 1 {
		line = 1
	}
	if col < 1 {
		col = 1
	}
	n := len(p.content)
	starts := p.lineStarts()
	if line-1 >= len(starts) {
		return n // past the last line: the walk stops at the end of content
	}
	start := starts[line-1]
	// The newline ending this line, or the end of content on the last line.
	lineEnd := n
	if line < len(starts) {
		lineEnd = starts[line] - 1
	}
	target := start + (col - 1)
	if target > n {
		target = n
	}
	if lineEnd < target {
		return lineEnd
	}
	return target
}

// line is LineForOffset's definition: 1 + the newlines in content[:off].
func (p *pinned) line(off int) int {
	if off > len(p.content) {
		off = len(p.content)
	}
	if off <= 0 {
		return 1
	}
	// starts[k] = (k-th newline)+1 for k >= 1, so a newline lies before off
	// exactly when its start is <= off.
	return sort.SearchInts(p.lineStarts(), off+1)
}

func (p *pinned) classify(lang Lang) ([]Region, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	r, ok := p.regions[lang]
	return r, ok
}

func (p *pinned) storeRegions(lang Lang, r []Region) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.regions == nil {
		p.regions = map[Lang][]Region{}
	}
	p.regions[lang] = r
}
