package findings

import (
	"testing"
)

// withFingerprintVersion swaps the active algorithm for the duration of
// a test and restores the prior value (not the package default) on
// Cleanup, so concurrent / sequential tests can't observe each other's
// state.
func withFingerprintVersion(t *testing.T, v FingerprintVersion) {
	t.Helper()
	prev := GetFingerprintVersion()
	SetFingerprintVersion(v)
	t.Cleanup(func() { SetFingerprintVersion(prev) })
}

// TestFingerprintV2_LineIndependent — the core promise of V2: shifting
// a finding up or down (import order changes, gofmt, comment edits)
// must not change its fingerprint.
func TestFingerprintV2_LineIndependent(t *testing.T) {
	withFingerprintVersion(t, FingerprintV2)

	loc1 := Location{FilePath: "http/middleware.go", StartLine: 60}
	loc2 := Location{FilePath: "http/middleware.go", StartLine: 59}

	fp1 := ComputeFingerprint("AI-012", loc1, "cb.Execute(ctx, fn)")
	fp2 := ComputeFingerprint("AI-012", loc2, "cb.Execute(ctx, fn)")

	if fp1 != fp2 {
		t.Errorf("V2 fingerprints differ across line numbers: %s vs %s", fp1, fp2)
	}
}

// TestFingerprintV2_PathNormalisation — scanning ./http vs . used to
// produce different fingerprints because the file_path differed by the
// leading "./" prefix and (on Windows) the separator. V2 normalises
// both away.
func TestFingerprintV2_PathNormalisation(t *testing.T) {
	withFingerprintVersion(t, FingerprintV2)

	// All four describe the same underlying file. Forward-slash and
	// leading-./ variants must all collapse to one fingerprint.
	paths := []string{
		"http/middleware.go",
		"./http/middleware.go",
		"http\\middleware.go", // Windows-style separators
		"http/./middleware.go",
	}
	var first string
	for i, p := range paths {
		fp := ComputeFingerprint("AI-012", Location{FilePath: p, StartLine: 60}, "x")
		if i == 0 {
			first = fp
			continue
		}
		if fp != first {
			t.Errorf("V2 fingerprints differ across path variants: %q yields %s vs baseline %s", p, fp, first)
		}
	}
}

// TestFingerprintV1_Preserved — V1 must still thread StartLine through
// the hash, so an import shift that moves a finding from line 42 to
// line 99 produces a different fingerprint under V1. This is the exact
// behaviour V2 was created to fix; the test pins V1 against accidental
// regressions toward the V2 algorithm.
func TestFingerprintV1_Preserved(t *testing.T) {
	withFingerprintVersion(t, FingerprintV1)

	loc1 := Location{FilePath: "cmd/server/main.go", StartLine: 42}
	loc2 := Location{FilePath: "cmd/server/main.go", StartLine: 99}

	fp1 := ComputeFingerprint("SEC001", loc1, "hardcoded credential")
	fp2 := ComputeFingerprint("SEC001", loc2, "hardcoded credential")

	if len(fp1) != 64 {
		t.Fatalf("expected 64-char hex, got %d", len(fp1))
	}
	if fp1 == fp2 {
		t.Errorf("V1 must vary with StartLine; got identical fingerprints across lines 42 and 99")
	}
}

// TestFingerprintV2_ContentStillMatters — V2 drops the line and
// normalises the path, but the rule_id and content still segment the
// space. Different content on the same line must yield different
// fingerprints.
func TestFingerprintV2_ContentStillMatters(t *testing.T) {
	withFingerprintVersion(t, FingerprintV2)

	loc := Location{FilePath: "main.go", StartLine: 10}
	a := ComputeFingerprint("SEC001", loc, "cb.Execute(ctx)")
	b := ComputeFingerprint("SEC001", loc, "db.Query(sql)")
	if a == b {
		t.Errorf("V2 must distinguish content; got identical fingerprints for distinct matches")
	}
}

// TestFingerprintV2_RuleIDStillMatters — same code flagged by two
// different rules must produce two different fingerprints. Without this
// the baseline file couldn't disambiguate them.
func TestFingerprintV2_RuleIDStillMatters(t *testing.T) {
	withFingerprintVersion(t, FingerprintV2)

	loc := Location{FilePath: "main.go", StartLine: 10}
	a := ComputeFingerprint("AI-012", loc, "cb.Execute(ctx)")
	b := ComputeFingerprint("SEC-001", loc, "cb.Execute(ctx)")
	if a == b {
		t.Errorf("V2 must distinguish rule_id; got identical fingerprints for distinct rules")
	}
}

// TestSetFingerprintVersion_RoundTrip — the public setter accepts both
// versions and rejects unknown values by falling back to the default.
func TestSetFingerprintVersion_RoundTrip(t *testing.T) {
	prev := GetFingerprintVersion()
	t.Cleanup(func() { SetFingerprintVersion(prev) })

	SetFingerprintVersion(FingerprintV2)
	if got := GetFingerprintVersion(); got != FingerprintV2 {
		t.Errorf("after SetFingerprintVersion(V2), got %d", got)
	}
	SetFingerprintVersion(FingerprintV1)
	if got := GetFingerprintVersion(); got != FingerprintV1 {
		t.Errorf("after SetFingerprintVersion(V1), got %d", got)
	}
	SetFingerprintVersion(FingerprintVersion(99))
	if got := GetFingerprintVersion(); got != DefaultFingerprintVersion {
		t.Errorf("after SetFingerprintVersion(99), expected fallback to default, got %d", got)
	}
}

// TestComputeFingerprintWith_ExplicitVersion — callers can mix versions
// in a single process (needed during baseline migration).
func TestComputeFingerprintWith_ExplicitVersion(t *testing.T) {
	loc := Location{FilePath: "main.go", StartLine: 10}
	v1 := ComputeFingerprintWith("SEC001", loc, "x", FingerprintV1)
	v2 := ComputeFingerprintWith("SEC001", loc, "x", FingerprintV2)
	if v1 == v2 {
		t.Error("V1 and V2 fingerprints unexpectedly collide for the same input")
	}
	if len(v1) != 64 || len(v2) != 64 {
		t.Fatalf("unexpected fingerprint shape: v1=%q v2=%q", v1, v2)
	}
}

// TestNormaliseFilePath_KnownCases pins the behaviour of the
// normalisation helper so future edits don't accidentally shift V2
// fingerprints.
func TestNormaliseFilePath_KnownCases(t *testing.T) {
	cases := map[string]string{
		"http/middleware.go":   "http/middleware.go",
		"./http/middleware.go": "http/middleware.go",
		"http\\middleware.go":  "http/middleware.go",
		"http/./middleware.go": "http/middleware.go",
		"./":                   "",
		".":                    "",
		"":                     "",
		"a/b/../c.go":          "a/c.go",
	}
	for in, want := range cases {
		if got := normaliseFilePath(in); got != want {
			t.Errorf("normaliseFilePath(%q) = %q, want %q", in, got, want)
		}
	}
}
