// Package source holds cross-analyzer classification of source files — the
// facts about a path or its contents that many analyzers need and had each been
// answering for themselves.
//
// The predicate that started it: "is this test code we should not report on?"
// It existed in four analyzers, and they had drifted — one normalised paths with
// strings.ToLower alone, so a Windows backslash path missed the test directory
// entirely; three recognised only Go test files while a fourth handled a dozen
// languages. This predicate DECIDES WHETHER FINDINGS ARE DROPPED, so a wrong or
// inconsistent answer either hides a vulnerability or floods the report with
// fixture noise. One tested implementation, here, is the fix.
package source

import "strings"

// testSuffixes are filename endings that identify test code across the languages
// nox analyses.
var testSuffixes = []string{
	"_test.go",
	".test.js", ".test.jsx", ".test.mjs", ".test.cjs",
	".test.ts", ".test.tsx",
	".spec.js", ".spec.jsx", ".spec.ts", ".spec.tsx",
	"_test.py",
	"_test.rb", "_spec.rb",
	"_test.rs",
	"test.java", "tests.java",
	"test.kt", "tests.kt",
	"test.cs", "tests.cs",
	"test.php", "tests.php",
	"test.swift", "tests.swift",
}

// testDirs are path fragments that identify a test tree. Only unambiguous ones:
// a bare `test/` is a real source directory in plenty of projects, and skipping
// it would silently drop findings rather than merely quieten fixtures.
var testDirs = []string{"testdata/", "__tests__/", "src/test/", "src/tests/"}

// IsTestPath reports whether a path is test code — a test file by name, or a
// file under a recognised test tree. Path separators are normalised to forward
// slash first, so the answer is the same on Windows and POSIX (the bug one
// copy carried by lower-casing without normalising).
func IsTestPath(p string) bool {
	// Normalise separators explicitly rather than via filepath.ToSlash, which is
	// a no-op off Windows: doing it here makes the answer identical on every OS,
	// which is the drift one copy had by lower-casing without normalising at all.
	lower := strings.ReplaceAll(strings.ToLower(p), "\\", "/")
	base := lower
	if i := strings.LastIndexByte(base, '/'); i >= 0 {
		base = base[i+1:]
	}
	for _, s := range testSuffixes {
		if strings.HasSuffix(base, s) {
			return true
		}
	}
	if strings.HasPrefix(base, "test_") {
		return true
	}
	for _, d := range testDirs {
		if strings.HasPrefix(lower, d) || strings.Contains(lower, "/"+d) {
			return true
		}
	}
	return false
}
