package main

import "testing"

// The comparison decides whether a security plugin runs, so the table is
// explicit about the boundaries rather than sampling the happy path.
func TestConstraintSatisfied(t *testing.T) {
	for _, tc := range []struct {
		constraint, installed string
		want                  bool
		wantErr               bool
	}{
		// Any.
		{"*", "0.2.2", true, false},
		{"", "0.2.2", true, false},
		{"*", "dev", true, false}, // no comparison needed, so no error

		// Exact.
		{"0.2.2", "0.2.2", true, false},
		{"0.2.2", "0.2.3", false, false},
		{"v0.2.2", "0.2.2", true, false},
		{"0.2.2", "v0.2.2", true, false},

		// Caret: compatible, not older. The case that started this.
		{"^0.2.0", "0.2.2", true, false},
		{"^0.2.0", "0.2.0", true, false},
		{"^0.2.0", "0.1.9", false, false},
		{"^0.2.0", "1.0.0", false, false},
		{"^1.2.3", "1.9.9", true, false},
		{"^1.2.3", "2.0.0", false, false},

		// The 0.x tiers. "^" admits changes that do not alter the left-most
		// NON-ZERO component, so below 1.0.0 the minor is the breaking axis.
		// Every plugin in the registry is 0.x, so reading "^" as "same major"
		// would make it mean "anything" for all of them — an operator writing
		// ^0.2.0 would silently accept 0.9.9. These are the cases that keep
		// the constraint worth writing.
		{"^0.2.0", "0.2.9", true, false},
		{"^0.2.0", "0.2.99", true, false},
		{"^0.2.0", "0.3.0", false, false},
		{"^0.2.0", "0.9.9", false, false},
		// npm and cargo tighten ^0.0.z to an exact match; this deliberately
		// does not, because no plugin in the registry is 0.0.x and the strict
		// reading would leave "^" unwritable for one that was. Pinned here so
		// the deviation is a decision with a test behind it rather than an
		// oversight — if the registry ever ships an 0.0.x plugin, this is the
		// case to revisit.
		{"^0.0.3", "0.0.3", true, false},
		{"^0.0.3", "0.0.4", true, false},
		{"^0.0.3", "0.1.0", false, false},

		// Tilde: same major AND minor, not older.
		{"~0.2.0", "0.2.9", true, false},
		{"~0.2.0", "0.3.0", false, false},
		{"~0.2.5", "0.2.4", false, false},

		// At least.
		{">=0.2.0", "0.2.0", true, false},
		{">=0.2.0", "9.9.9", true, false},
		{">=0.2.0", "0.1.9", false, false},

		// A version that cannot be compared must not silently pass a pin.
		{"^0.2.0", "dev", false, true},
		{"0.2.2", "v0.10.0-3-gabc", false, true},

		// Unsupported grammar is an error, never a silent pass: a constraint
		// nobody enforces is worse than none, because the operator believes a
		// version is pinned and it is not.
		{"<1.0.0", "0.2.2", false, true},
		{">0.2.0", "0.2.2", false, true},
		{"latest", "0.2.2", false, true},
		// A *bare* partial stays an error — "0.2" could mean exactly 0.2.0 or
		// any 0.2.x. An operator form disambiguates it and is accepted; see
		// TestConstraintSatisfied_PartialVersions.
		{"0.2", "0.2.2", false, true},
	} {
		got, err := constraintSatisfied(tc.constraint, tc.installed)
		if (err != nil) != tc.wantErr {
			t.Errorf("constraintSatisfied(%q, %q) err = %v, wantErr %v",
				tc.constraint, tc.installed, err, tc.wantErr)
			continue
		}
		if got != tc.want {
			t.Errorf("constraintSatisfied(%q, %q) = %v, want %v",
				tc.constraint, tc.installed, got, tc.want)
		}
	}
}

func TestParseVersion(t *testing.T) {
	for _, s := range []string{"1.2.3", "v1.2.3", "0.0.0", "10.20.30"} {
		if _, err := parseVersion(s); err != nil {
			t.Errorf("parseVersion(%q) = %v, want success", s, err)
		}
	}
	// Pre-release and build metadata are rejected rather than truncated:
	// treating 1.2.3-rc1 as 1.2.3 would let a release candidate satisfy a
	// constraint written to exclude it.
	for _, s := range []string{"1.2", "1.2.3.4", "dev", "", "1.2.x", "1.2.3-rc1", "a.b.c", "-1.2.3"} {
		if _, err := parseVersion(s); err == nil {
			t.Errorf("parseVersion(%q) succeeded, want an error", s)
		}
	}
}

func TestParsedVersionCompare(t *testing.T) {
	mk := func(s string) parsedVersion {
		v, err := parseVersion(s)
		if err != nil {
			t.Fatalf("parseVersion(%q): %v", s, err)
		}
		return v
	}
	for _, tc := range []struct {
		a, b string
		want int
	}{
		{"1.2.3", "1.2.3", 0},
		{"1.2.4", "1.2.3", 1},
		{"1.2.3", "1.2.4", -1},
		{"1.3.0", "1.2.9", 1},
		{"2.0.0", "1.9.9", 1},
		{"0.2.2", "0.2.10", -1}, // numeric, not lexical
	} {
		if got := mk(tc.a).compare(mk(tc.b)); got != tc.want {
			t.Errorf("compare(%s, %s) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

// The README documents `nox/reachability@>=0.5`. An operator form may carry a
// partial version; a bare one stays ambiguous and so stays rejected.
func TestConstraintSatisfied_PartialVersions(t *testing.T) {
	for _, tc := range []struct {
		constraint, installed string
		want, wantErr         bool
	}{
		{">=0.5", "0.5.2", true, false},
		{">=0.5", "0.4.9", false, false},
		{">=1", "1.0.0", true, false},
		{"^0.5", "0.5.9", true, false},
		{"^0.5", "0.6.0", false, false},
		{"~0.5", "0.5.9", true, false},
		{"~0.5", "0.6.0", false, false},

		// Bare partials remain unsupported: 0.5 could mean 0.5.0 exactly or
		// any 0.5.x, and picking one silently would be a guess.
		{"0.5", "0.5.2", false, true},
		{"1", "1.0.0", false, true},
	} {
		got, err := constraintSatisfied(tc.constraint, tc.installed)
		if (err != nil) != tc.wantErr {
			t.Errorf("constraintSatisfied(%q, %q) err = %v, wantErr %v", tc.constraint, tc.installed, err, tc.wantErr)
			continue
		}
		if err == nil && got != tc.want {
			t.Errorf("constraintSatisfied(%q, %q) = %v, want %v", tc.constraint, tc.installed, got, tc.want)
		}
	}
}
