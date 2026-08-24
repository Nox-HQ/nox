package rules

import (
	"testing"
	"time"
)

// FuzzScanFile fuzzes arbitrary content through the rule engine with a
// representative set of rules. This exercises regex matching, keyword
// filtering, and the entire ScanFile code path with random inputs.
func FuzzScanFile(f *testing.F) {
	// nox:ignore SEC-001,SEC-078,SEC-100 -- fuzz seed corpus with intentional security patterns
	f.Add([]byte("AKIAIOSFODNN7EXAMPLE"), "main.go")
	f.Add([]byte("password = 'secret123'"), "config.py")
	f.Add([]byte("{}"), "test.json")
	f.Add([]byte(""), "empty.txt")
	f.Add([]byte("BEGIN RSA PRIVATE KEY"), "key.pem")
	f.Add([]byte("\x00\x01\x02binary"), "file.bin")
	f.Add([]byte("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef12"), "token.txt")
	f.Add([]byte("resource \"aws_s3_bucket\" {}"), "main.tf")

	// Build a RuleSet with representative rules for fuzzing.
	rs := NewRuleSet()
	rs.Add(&Rule{
		ID:          "FUZZ-001",
		Description: "Test regex rule",
		Severity:    "high",
		MatcherType: "regex",
		Pattern:     `(?i)password\s*[:=]\s*['"][^'"]+['"]`,
		Version:     "1.0",
	})
	rs.Add(&Rule{
		ID:          "FUZZ-002",
		Description: "Test keyword rule",
		Severity:    "medium",
		MatcherType: "regex",
		Pattern:     `AKIA[0-9A-Z]{16}`,
		Keywords:    []string{"AKIA"},
		Version:     "1.0",
	})
	rs.Add(&Rule{
		ID:           "FUZZ-003",
		Description:  "Test file pattern rule",
		Severity:     "low",
		MatcherType:  "regex",
		Pattern:      `BEGIN.*PRIVATE KEY`,
		FilePatterns: []string{"*.pem", "*.key"},
		Version:      "1.0",
	})

	engine := NewEngine(rs)

	f.Fuzz(func(t *testing.T, content []byte, path string) {
		// Must not panic regardless of input.
		start := time.Now()
		_, _ = engine.ScanFile(path, content)
		elapsed := time.Since(start)

		// ...and must not HANG on any input either.
		//
		// This bound exists because a stall here is otherwise undiagnosable.
		// When ScanFile takes long enough, the fuzzing coordinator gives up on
		// the worker and reports "context deadline exceeded" — which reads like
		// flaky infrastructure, names no input, and writes NO corpus entry, so
		// there is nothing to reproduce from. That is exactly what happened on
		// main at 28e0ca79: repeated "0/sec" windows, then a timeout, and no
		// reproducer. A quadratic in findLine was found and fixed afterwards by
		// benchmarking, but whether it was the cause was never established.
		//
		// Failing INSIDE the fuzz function instead names the input in the test
		// output, and — when the offender is one the fuzzer DISCOVERED rather
		// than a seed — Go writes it to testdata/fuzz/FuzzScanFile/ as a
		// checked-in regression case. (A seed that trips this is reported but
		// not written, since it already lives in the source.) Either way the
		// failure stops being a bare timeout with nothing attached.
		//
		// The bound is deliberately enormous — six orders of magnitude above the
		// microseconds a real scan of a fuzz-sized input takes — so a loaded
		// runner cannot trip it. A tight bound on a path that normally costs
		// nothing is how you manufacture a flake; only a genuine stall reaches
		// this.
		if elapsed > maxScanFileDuration {
			t.Fatalf("ScanFile took %v for %d bytes and path %q, over the %v bound; "+
				"a scan this slow is a pathological input. If the fuzzer discovered it, "+
				"Go has written it to testdata/fuzz/FuzzScanFile for reproduction",
				elapsed, len(content), path, maxScanFileDuration)
		}
	})
}

// maxScanFileDuration bounds a single ScanFile call under fuzzing. See the
// comment in FuzzScanFile for why it is this generous.
const maxScanFileDuration = 10 * time.Second

// FuzzContainsAnyKeyword fuzzes the keyword matching function with
// arbitrary content and keyword combinations.
func FuzzContainsAnyKeyword(f *testing.F) {
	f.Add([]byte("api_key"), "api_key")
	f.Add([]byte("password"), "password")
	f.Add([]byte("nothing here"), "secret")
	f.Add([]byte(""), "")
	f.Add([]byte("mixed CASE content"), "case")

	f.Fuzz(func(t *testing.T, content []byte, keyword string) {
		if keyword == "" {
			return
		}
		_ = containsAnyKeyword(content, []string{keyword})
	})
}
