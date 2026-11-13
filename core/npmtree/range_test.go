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
		{"1.20.9", "^1.0.0-beta.1", false, false},
	}
	for _, c := range cases {
		in, known := satisfiesNPMRange(v(c.version), c.rng)
		if in != c.in || known != c.known {
			t.Errorf("%s in %q = (%v,%v), want (%v,%v)", c.version, c.rng, in, known, c.in, c.known)
		}
	}
}
