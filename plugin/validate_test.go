package plugin

import "testing"

func TestIsSafeName(t *testing.T) {
	safe := []string{"nox/reachability", "nox-plugin-foo", "a.b_c-d", "vendor/pkg1"}
	for _, s := range safe {
		if !IsSafeName(s) {
			t.Errorf("IsSafeName(%q) = false, want true", s)
		}
	}
	unsafe := []string{
		"",               // empty
		"../etc/passwd",  // traversal
		"nox/../../root", // traversal mid-string
		".hidden",        // leading dot
		"-flag",          // leading dash
		"/abs",           // leading slash
		"name;rm -rf",    // shell metachar
		"a b",            // space
		"pkg$(whoami)",   // injection
	}
	for _, s := range unsafe {
		if IsSafeName(s) {
			t.Errorf("IsSafeName(%q) = true, want false (security allowlist)", s)
		}
	}
	// Overlong.
	long := make([]byte, 201)
	for i := range long {
		long[i] = 'a'
	}
	if IsSafeName(string(long)) {
		t.Error("a 201-char name should be rejected")
	}
}

func TestIsSafeVersionConstraint(t *testing.T) {
	for _, s := range []string{"1.2.3", ">=1.0.0", "^2.1", "~1.4.0-rc.1", "1.0.0+build"} {
		if !IsSafeVersionConstraint(s) {
			t.Errorf("IsSafeVersionConstraint(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"", "1.0.0; rm -rf /", "$(x)", "1.0 2.0", "../1.0"} {
		if IsSafeVersionConstraint(s) {
			t.Errorf("IsSafeVersionConstraint(%q) = true, want false", s)
		}
	}
}
