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
	"time"

	"github.com/nox-hq/nox/core/discovery"
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

// TestDedupScalesWithFindingsPerFile is the regression bound. It measures
// growth, not speed: the same input shape at 256 KB and at 1 MB, scanned
// under the same machine load, must take well under the 16x a quadratic
// pipeline needs for 4x the bytes -- linear is ~4x. A fixed wall-clock limit
// was tried first and failed on a CI-like machine at load 25 on 10 cores,
// where a linear 1 MB scan took 10.7 s. A loose absolute ceiling stays as a
// backstop; the quadratic pipeline took 39 s and 22 s at 1 MB.
func TestDedupScalesWithFindingsPerFile(t *testing.T) {
	if testing.Short() {
		t.Skip("scans 2.5 MB")
	}
	// fastest of a few runs: noise only ever adds time.
	timeScan := func(file, content string) (time.Duration, int) {
		best, n := time.Duration(1<<62), 0
		for range 3 {
			start := time.Now()
			n = scanOneFile(t, file, content)
			best = min(best, time.Since(start))
		}
		return best, n
	}
	for _, c := range []struct {
		name, file string
		gen        func(seed int64, bytes int) string
	}{
		{"compact JWTs", "tokens.py", compactJWTFile},
		{"pretty JWTs in prose", "tokens.md", prettyJWTProse},
	} {
		small, nSmall := timeScan(c.file, c.gen(1, 256<<10))
		large, nLarge := timeScan(c.file, c.gen(1, 1<<20))
		if nLarge < 4000 || nLarge < 3*nSmall {
			t.Fatalf("%s: %d then %d findings; the inputs are meant to carry thousands, growing with size", c.name, nSmall, nLarge)
		}
		ratio := float64(large) / float64(small)
		t.Logf("%s: %d findings in %v, %d in %v (x%.1f for x4 the bytes)", c.name, nSmall, small, nLarge, large, ratio)
		if ratio > 8 {
			t.Errorf("%s: 4x the bytes took x%.1f the time; the per-file pipeline is meant to be linear (~x4), not quadratic (~x16)", c.name, ratio)
		}
		if large > 60*time.Second {
			t.Errorf("%s: %v for 1 MB", c.name, large)
		}
	}
}
