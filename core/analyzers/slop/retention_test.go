package slop

import (
	"runtime"
	"strings"
	"testing"
)

// Package names come out of a lockfile as substrings of the whole file, and a
// map key that is a substring keeps the entire file alive: on llama_index the
// declared set held 480 MB of uv.lock text through a few thousand names. A set
// built from a large lockfile must not keep the lockfile.
func TestDeclaredSetDoesNotRetainTheLockfile(t *testing.T) {
	const size = 64 << 20
	var b strings.Builder
	b.Grow(size + 1024)
	for _, name := range []string{"requests", "typing-extensions", "zope.interface"} {
		b.WriteString("[[package]]\nname = \"" + name + "\"\nversion = \"1.0\"\n\n")
	}
	pad := strings.Repeat("# padding padding padding padding padding padding padding\n", 1024)
	for b.Len() < size {
		b.WriteString(pad)
	}

	d := newDeclaredSet()
	func() {
		content := []byte(b.String())
		b.Reset()
		addDeclared(d, "uv.lock", content)
	}()
	if !d.hasPyPI("requests") || !d.hasPyPI("zope") {
		t.Fatal("test premise: the lockfile's packages are declared")
	}

	runtime.GC()
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	if m.HeapInuse > size/4 {
		t.Errorf("%d MB still in use after a 64 MB lockfile was parsed and dropped; the declared set keeps it alive", m.HeapInuse>>20)
	}
	runtime.KeepAlive(d)
}
