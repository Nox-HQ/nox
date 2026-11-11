package fix

import "testing"

func TestSpelledLike(t *testing.T) {
	tests := []struct{ installed, version, want string }{
		{"v0.58.0", "0.58.1-0.20261009181718-2f1f834330b2", "v0.58.1-0.20261009181718-2f1f834330b2"},
		{"v0.58.0", "v0.59.0", "v0.59.0"},
		{"1.6.0", "1.8.2", "1.8.2"},
		{"", "1.8.2", "1.8.2"},
		{"v1.0.0", "", ""},
		{"1.3.2-r1", "1.4-r0", "1.4-r0"},
	}
	for _, tc := range tests {
		if got := SpelledLike(tc.installed, tc.version); got != tc.want {
			t.Errorf("SpelledLike(%q, %q) = %q, want %q", tc.installed, tc.version, got, tc.want)
		}
	}
}
