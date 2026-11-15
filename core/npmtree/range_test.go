package npmtree

import "testing"

func TestNPMRanges(t *testing.T) {
	v := func(s string) npmVersion { x, _ := parseNPMVersion(s); return x }
	cases := []struct {
		version, rng string
		in, known    bool
	}{
		{"6.16.0", "^6.11.0", true, true},
		{"6.16.0", "6.13.0", false, true},
		{"6.16.0", "~6.13.0", false, true},
		{"6.13.5", "~6.13.0", true, true},
		{"7.0.0", "^6.11.0", false, true},
		{"0.2.5", "^0.2.0", true, true},
		{"0.3.0", "^0.2.0", false, true},
		{"1.20.9", "1.x", true, true},
		{"1.20.9", "*", true, true},
		{"1.20.9", ">=1.20.0 <1.20.5", false, true},
		{"1.20.9", ">=1.20.0 <2", true, true},
		{"1.20.9", "1.0.0 - 1.20.5", false, true},
		{"1.20.9", "<1.0.0 || ^1.20.0", true, true},
		{"1.20.9", "latest", false, false},
		{"1.20.9", "git+https://example.com/x.git", false, false},
		// A bound tagged as a pre-release is exact for a release version:
		// nothing is released between X.Y.Z-pre and X.Y.Z, so >= and > of the
		// bound are >= X.Y.Z, < and <= are < X.Y.Z, and = matches no release.
		// The vite ecosystem writes its peer ranges this way; read as
		// unknown, they made nox report vite 6.4.1 as held below 6.4.5.
		{"1.20.9", "^1.0.0-beta.1", true, true},
		{"6.4.5", "^6.0.0-0", true, true},
		{"7.0.0", "^6.0.0-0", false, true},
		{"6.4.5", "^2.6.0 || ^3.0.0 || ^4.0.0 || ^5.0.0-0 || ^6.0.0-0 || ^7.0.0-0", true, true},
		{"6.4.5", "^3.1.0 || ^4.0.0 || ^5.0.0-0 || ^6.0.1", true, true},
		{"1.2.3", ">=1.2.3-rc.1", true, true},
		{"1.2.2", ">=1.2.3-rc.1", false, true},
		{"1.2.3", ">1.2.3-rc.1", true, true},
		{"1.2.3", "<1.2.3-rc.1", false, true},
		{"1.2.2", "<1.2.3-rc.1", true, true},
		{"1.2.3", "<=1.2.3-rc.1", false, true},
		{"1.2.3", "1.2.3-rc.1", false, true},
		{"1.2.3", "=1.2.3-rc.1", false, true},
		{"1.2.9", "~1.2.3-beta", true, true},
		{"1.3.0", "~1.2.3-beta", false, true},
		{"0.0.3", "^0.0.3-beta", true, true},
		{"0.0.4", "^0.0.3-beta", false, true},
		{"1.2.3", "1.0.0-alpha - 1.2.3-beta", false, true},
		{"1.2.2", "1.0.0-alpha - 1.2.3-beta", true, true},
		// Build metadata has no precedence; it is ignored, not guessed at.
		{"1.2.3", "1.2.3+build.5", true, true},
		// A pre-release tag on a partial version is not a form npm defines.
		{"1.2.3", "^1.2-beta", false, false},
	}
	for _, c := range cases {
		in, known := satisfiesNPMRange(v(c.version), c.rng)
		if in != c.in || known != c.known {
			t.Errorf("%s in %q = (%v,%v), want (%v,%v)", c.version, c.rng, in, known, c.in, c.known)
		}
	}
}
