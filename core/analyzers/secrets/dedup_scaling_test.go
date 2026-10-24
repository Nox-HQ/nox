package secrets

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/internal/workcount"
	"github.com/nox-hq/nox/core/lexctx"
)

// The secrets pipeline's cost per file must not grow with findings x
// findings or findings x file size. Both shapes below were measured
// quadratic before this file existed: 14.5k compact JWTs in one 5 MB file
// took 232 s, and 1 MB of pretty-printed JWTs in prose took 17 s once
// SEC-952 (#826) began reporting them. A file in an untrusted repository can
// be written to look like either, so the bound is a CI-stall guard.

// scalingJWT returns a signed HS256 JWT; pretty selects a non-compact header.
func scalingJWT(r *rand.Rand, pretty bool) string {
	enc := base64.RawURLEncoding
	header := `{"alg":"HS256","typ":"JWT"}`
	if pretty {
		header = "{\n  \"alg\": \"HS256\",\n  \"typ\": \"JWT\"\n}"
	}
	claims, _ := json.Marshal(map[string]any{"sub": fmt.Sprintf("u%09d", r.Intn(1e9)), "iat": 1759500000 + r.Intn(1e6)})
	sig := make([]byte, 32)
	r.Read(sig)
	return enc.EncodeToString([]byte(header)) + "." + enc.EncodeToString(claims) + "." + enc.EncodeToString(sig)
}

// compactJWTFile is a Python file of size >= bytes, one assigned JWT per line.
func compactJWTFile(seed int64, bytes int) string {
	r := rand.New(rand.NewSource(seed))
	var b strings.Builder
	for i := 0; b.Len() < bytes; i++ {
		fmt.Fprintf(&b, "token_%d = \"%s\"\n", i, scalingJWT(r, false))
	}
	return b.String()
}

// prettyJWTProse is Markdown of size >= bytes, one pretty-header JWT per line.
func prettyJWTProse(seed int64, bytes int) string {
	r := rand.New(rand.NewSource(seed))
	var b strings.Builder
	for b.Len() < bytes {
		fmt.Fprintf(&b, "Token: %s\n", scalingJWT(r, true))
	}
	return b.String()
}

func scanOneFile(tb testing.TB, name, content string) int {
	tb.Helper()
	dir := tb.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		tb.Fatal(err)
	}
	fs, err := NewAnalyzer().ScanArtifacts(context.Background(), []discovery.Artifact{{Path: name, AbsPath: path}})
	if err != nil {
		tb.Fatal(err)
	}
	return len(fs.Findings())
}

func BenchmarkScanCompactJWTs1MB(b *testing.B) {
	content := compactJWTFile(1, 1<<20)
	for b.Loop() {
		scanOneFile(b, "tokens.py", content)
	}
}

func BenchmarkScanPrettyJWTProse1MB(b *testing.B) {
	content := prettyJWTProse(2, 1<<20)
	for b.Loop() {
		scanOneFile(b, "tokens.md", content)
	}
}

// countScan scans one file with the work counters on and returns the
// findings and the work each quadratic-prone operation did.
func countScan(t *testing.T, name, content string) (int, workcount.Counts) {
	t.Helper()
	stop := workcount.Start()
	n := scanOneFile(t, name, content)
	return n, stop()
}

// TestDedupScalesWithFindingsPerFile is the regression bound. It counts
// work, not time: the same input shape at 256 KB and at 1 MB must make each
// operation that once went quadratic -- offset walks, lexing, the data: URI
// search, dedup's comparisons -- do about 4x the work for 4x the bytes. A
// quadratic one does ~16x.
//
// It used to decide by wall-clock ratio, best of 3, with a 60 s ceiling. That
// flaked: Windows CI took 60.011 s for a linear 1 MB scan, and pre-push runs
// at load 80-160 measured x12.1. Counts are the same on every machine and
// under any load. Each of #827's fixes, reverted alone, grows its count
// x15.9-x16.0: dropping the Pin (offset walks, and lexing for .py), scanning
// every finding per dedup anchor, and searching for data: per finding.
func TestDedupScalesWithFindingsPerFile(t *testing.T) {
	if testing.Short() {
		t.Skip("scans 2.5 MB")
	}
	// The bound below is only as good as the counting, so first prove that a
	// walk from byte 0 -- the cost a missing index pays -- is counted.
	unpinned := []byte(strings.Repeat("x = 1\n", 100))
	stop := workcount.Start()
	lexctx.LineColToOffset(unpinned, 100, 1)
	if got := stop()[workcount.OffsetWalk]; got != 99*6 {
		t.Fatalf("an unpinned offset lookup walking %d bytes counted %d; the work counters are not wired", 99*6, got)
	}

	cases := []struct{ name, file string }{
		{"compact JWTs", "tokens.py"},
		{"pretty JWTs in prose", "tokens.md"},
	}
	gens := []func(seed int64, bytes int) string{compactJWTFile, prettyJWTProse}
	for i, c := range cases {
		smallContent, largeContent := gens[i](1, 256<<10), gens[i](1, 1<<20)
		nSmall, small := countScan(t, c.file, smallContent)
		nLarge, large := countScan(t, c.file, largeContent)
		if nLarge < 4000 || nLarge < 3*nSmall {
			t.Fatalf("%s: %d then %d findings; the inputs are meant to carry thousands, growing with size", c.name, nSmall, nLarge)
		}
		growth := float64(len(largeContent)) / float64(len(smallContent))
		// Both shapes carry thousands of findings, so both must convert
		// offsets and deduplicate; Markdown is not lexed at all.
		for _, k := range []workcount.Kind{workcount.OffsetWalk, workcount.DedupVisit} {
			if small[k] == 0 || large[k] == 0 {
				t.Errorf("%s: %v counted %d then %d; the scan is meant to do this work", c.name, k, small[k], large[k])
			}
		}
		for _, k := range workcount.Kinds() {
			if small[k] == 0 && large[k] == 0 {
				continue
			}
			ratio := float64(large[k]) / float64(small[k])
			t.Logf("%s: %v %d -> %d (x%.1f for x%.1f the bytes; %d -> %d findings)", c.name, k, small[k], large[k], ratio, growth, nSmall, nLarge)
			// Linear is x1 the growth and quadratic x4; x2 leaves room for
			// a per-finding constant that varies with the input's content.
			if ratio > 2*growth {
				t.Errorf("%s: %v grew x%.1f for x%.1f the bytes; the per-file pipeline is meant to be linear, not quadratic (~x%.0f)", c.name, k, ratio, growth, growth*growth)
			}
		}
	}
}
