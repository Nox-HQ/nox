package fix

import "testing"

func TestBumpKind(t *testing.T) {
	cases := []struct {
		from, to string
		want     Bump
	}{
		{"1.2.3", "1.2.4", BumpPatch},
		{"1.2.3", "1.3.0", BumpMinor},
		{"v1.9.0", "v2.0.0", BumpMajor},
		{"1.2", "1.2.1", BumpPatch},
		{"", "1.2.1", BumpUnknown},
		{"main", "1.2.1", BumpUnknown},
		{"1.2.3", "next", BumpUnknown},
	}
	for _, c := range cases {
		if got := BumpKind(c.from, c.to); got != c.want {
			t.Errorf("BumpKind(%q, %q) = %q, want %q", c.from, c.to, got, c.want)
		}
	}
}
