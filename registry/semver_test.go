package registry

import "testing"

func TestParseVersion(t *testing.T) {
	tests := []struct {
		input   string
		want    Version
		wantErr bool
	}{
		{"1.2.3", Version{1, 2, 3, ""}, false},
		{"0.0.0", Version{0, 0, 0, ""}, false},
		{"10.20.30", Version{10, 20, 30, ""}, false},
		{"1.2.3-beta.1", Version{1, 2, 3, "beta.1"}, false},
		{"1.2.3-rc1", Version{1, 2, 3, "rc1"}, false},
		{"v1.2.3", Version{1, 2, 3, ""}, false},
		{"1.0", Version{1, 0, 0, ""}, false},
		{"1", Version{1, 0, 0, ""}, false},
		{"", Version{}, true},
		{"abc", Version{}, true},
		{"1.2.3.4", Version{}, true},
		{"1.-1.0", Version{}, true},
		{"1.2.3-", Version{}, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseVersion(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseVersion(%q) error = %v, wantErr = %v", tt.input, err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("ParseVersion(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestVersionString(t *testing.T) {
	tests := []struct {
		v    Version
		want string
	}{
		{Version{1, 2, 3, ""}, "1.2.3"},
		{Version{0, 0, 0, ""}, "0.0.0"},
		{Version{1, 2, 3, "beta.1"}, "1.2.3-beta.1"},
	}
	for _, tt := range tests {
		got := tt.v.String()
		if got != tt.want {
			t.Errorf("%v.String() = %q, want %q", tt.v, got, tt.want)
		}
	}
}

func TestVersionCompare(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.0", 0},
		{"1.0.0", "2.0.0", -1},
		{"2.0.0", "1.0.0", 1},
		{"1.1.0", "1.0.0", 1},
		{"1.0.1", "1.0.0", 1},
		{"1.0.0", "1.0.0-alpha", 1},  // stable > pre-release
		{"1.0.0-alpha", "1.0.0", -1}, // pre-release < stable
		{"1.0.0-alpha", "1.0.0-beta", -1},
		{"1.0.0-beta", "1.0.0-alpha", 1},
		{"1.0.0-rc1", "1.0.0-rc1", 0},
	}
	for _, tt := range tests {
		t.Run(tt.a+"_vs_"+tt.b, func(t *testing.T) {
			a, _ := ParseVersion(tt.a)
			b, _ := ParseVersion(tt.b)
			got := a.Compare(b)
			if got != tt.want {
				t.Errorf("%s.Compare(%s) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestVersionLessThan(t *testing.T) {
	a, _ := ParseVersion("1.0.0")
	b, _ := ParseVersion("2.0.0")
	if !a.LessThan(b) {
		t.Error("1.0.0 should be less than 2.0.0")
	}
	if b.LessThan(a) {
		t.Error("2.0.0 should not be less than 1.0.0")
	}
}

func TestParseConstraint(t *testing.T) {
	tests := []struct {
		input   string
		wantErr bool
	}{
		{">=1.0.0", false},
		{"^1.0.0", false},
		{"~1.0.0", false},
		{"1.0.0", false},
		{"*", false},
		{"", true},
		{">=abc", true},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			_, err := ParseConstraint(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseConstraint(%q) error = %v, wantErr = %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestConstraintMatch(t *testing.T) {
	tests := []struct {
		constraint string
		version    string
		want       bool
	}{
		// Exact match
		{"1.2.3", "1.2.3", true},
		{"1.2.3", "1.2.4", false},
		{"1.2.3", "1.2.2", false},

		// Greater than or equal
		{">=1.0.0", "1.0.0", true},
		{">=1.0.0", "2.0.0", true},
		{">=1.0.0", "0.9.0", false},
		{">=1.2.0", "1.2.0", true},
		{">=1.2.0", "1.3.0", true},
		{">=1.2.0", "1.1.0", false},

		// Caret (compatible: same major)
		{"^1.2.0", "1.2.0", true},
		{"^1.2.0", "1.9.9", true},
		{"^1.2.0", "1.2.1", true},
		{"^1.2.0", "2.0.0", false},
		{"^1.2.0", "1.1.0", false},
		// Caret with major 0 (same minor)
		{"^0.2.0", "0.2.0", true},
		{"^0.2.0", "0.2.5", true},
		{"^0.2.0", "0.3.0", false},
		{"^0.2.0", "1.0.0", false},

		// Tilde (approximately: same minor)
		{"~1.2.0", "1.2.0", true},
		{"~1.2.0", "1.2.9", true},
		{"~1.2.0", "1.3.0", false},
		{"~1.2.0", "1.1.0", false},
		{"~1.2.0", "2.0.0", false},

		// Any
		{"*", "0.0.0", true},
		{"*", "99.99.99", true},
		{"*", "1.0.0-alpha", true},
	}

	for _, tt := range tests {
		t.Run(tt.constraint+"_"+tt.version, func(t *testing.T) {
			c, err := ParseConstraint(tt.constraint)
			if err != nil {
				t.Fatalf("ParseConstraint(%q): %v", tt.constraint, err)
			}
			v, err := ParseVersion(tt.version)
			if err != nil {
				t.Fatalf("ParseVersion(%q): %v", tt.version, err)
			}
			got := c.Match(v)
			if got != tt.want {
				t.Errorf("Constraint(%q).Match(%q) = %v, want %v", tt.constraint, tt.version, got, tt.want)
			}
		})
	}
}

func TestConstraintString(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"*", "*"},
		{">=1.0.0", ">=1.0.0"},
		{"^1.2.3", "^1.2.3"},
		{"~1.2.3", "~1.2.3"},
		{"1.2.3", "1.2.3"},
	}
	for _, tt := range tests {
		c, err := ParseConstraint(tt.input)
		if err != nil {
			t.Fatalf("ParseConstraint(%q): %v", tt.input, err)
		}
		got := c.String()
		if got != tt.want {
			t.Errorf("Constraint(%q).String() = %q, want %q", tt.input, got, tt.want)
		}
	}
}
