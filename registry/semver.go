package registry

import (
	"fmt"
	"strconv"
	"strings"
)

// Version represents a parsed semantic version (major.minor.patch with optional pre-release).
type Version struct {
	Major int
	Minor int
	Patch int
	Pre   string // pre-release suffix (empty for stable releases)
}

// ParseVersion parses a semver string like "1.2.3" or "1.2.3-beta.1".
func ParseVersion(s string) (Version, error) {
	s = strings.TrimPrefix(s, "v")
	if s == "" {
		return Version{}, fmt.Errorf("empty version string")
	}

	var pre string
	if idx := strings.IndexByte(s, '-'); idx >= 0 {
		pre = s[idx+1:]
		s = s[:idx]
		if pre == "" {
			return Version{}, fmt.Errorf("empty pre-release suffix")
		}
	}

	parts := strings.Split(s, ".")
	if len(parts) < 1 || len(parts) > 3 {
		return Version{}, fmt.Errorf("invalid version %q: expected major[.minor[.patch]]", s)
	}

	nums := [3]int{}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return Version{}, fmt.Errorf("invalid version component %q: %w", p, err)
		}
		if n < 0 {
			return Version{}, fmt.Errorf("negative version component %d", n)
		}
		nums[i] = n
	}

	return Version{Major: nums[0], Minor: nums[1], Patch: nums[2], Pre: pre}, nil
}

// String returns the canonical version string.
func (v Version) String() string {
	s := fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
	if v.Pre != "" {
		s += "-" + v.Pre
	}
	return s
}

// Compare returns -1 if v < other, 0 if equal, 1 if v > other.
// Pre-release versions have lower precedence than stable versions
// with the same major.minor.patch.
func (v Version) Compare(other Version) int {
	if c := cmpInt(v.Major, other.Major); c != 0 {
		return c
	}
	if c := cmpInt(v.Minor, other.Minor); c != 0 {
		return c
	}
	if c := cmpInt(v.Patch, other.Patch); c != 0 {
		return c
	}
	return comparePre(v.Pre, other.Pre)
}

// LessThan returns true if v < other.
func (v Version) LessThan(other Version) bool {
	return v.Compare(other) < 0
}

func cmpInt(a, b int) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}

// comparePre compares pre-release strings.
// No pre-release (stable) > any pre-release.
// When both have pre-release, compare lexicographically.
func comparePre(a, b string) int {
	if a == b {
		return 0
	}
	if a == "" {
		return 1 // stable > pre-release
	}
	if b == "" {
		return -1 // pre-release < stable
	}
	if a < b {
		return -1
	}
	return 1
}

// Constraint represents a version constraint like ">=1.2.0", "^1.0.0", "~1.2.0", "1.2.0", or "*".
type Constraint struct {
	op      constraintOp
	version Version
}

type constraintOp int

const (
	opExact constraintOp = iota
	opGTE                // >=
	opCaret              // ^ (compatible: same major)
	opTilde              // ~ (approximately: same minor)
	opAny                // *
)

// ParseConstraint parses a version constraint string.
// Supported formats: ">=1.2.0", "^1.0.0", "~1.2.0", "1.2.0" (exact), "*" (any).
func ParseConstraint(s string) (Constraint, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Constraint{}, fmt.Errorf("empty constraint string")
	}

	if s == "*" {
		return Constraint{op: opAny}, nil
	}

	var op constraintOp
	var versionStr string

	switch {
	case strings.HasPrefix(s, ">="):
		op = opGTE
		versionStr = strings.TrimSpace(s[2:])
	case strings.HasPrefix(s, "^"):
		op = opCaret
		versionStr = strings.TrimSpace(s[1:])
	case strings.HasPrefix(s, "~"):
		op = opTilde
		versionStr = strings.TrimSpace(s[1:])
	default:
		op = opExact
		versionStr = s
	}

	v, err := ParseVersion(versionStr)
	if err != nil {
		return Constraint{}, fmt.Errorf("invalid constraint %q: %w", s, err)
	}

	return Constraint{op: op, version: v}, nil
}

// Match returns true if the given version satisfies this constraint.
func (c Constraint) Match(v Version) bool {
	switch c.op {
	case opAny:
		return true
	case opExact:
		return v.Compare(c.version) == 0
	case opGTE:
		return v.Compare(c.version) >= 0
	case opCaret:
		// ^1.2.3 → >=1.2.3, <2.0.0
		// ^0.2.3 → >=0.2.3, <0.3.0 (special case: major 0)
		if v.Compare(c.version) < 0 {
			return false
		}
		if c.version.Major == 0 {
			return v.Major == 0 && v.Minor == c.version.Minor
		}
		return v.Major == c.version.Major
	case opTilde:
		// ~1.2.3 → >=1.2.3, <1.3.0
		if v.Compare(c.version) < 0 {
			return false
		}
		return v.Major == c.version.Major && v.Minor == c.version.Minor
	default:
		return false
	}
}

// String returns the canonical constraint string.
func (c Constraint) String() string {
	switch c.op {
	case opAny:
		return "*"
	case opGTE:
		return ">=" + c.version.String()
	case opCaret:
		return "^" + c.version.String()
	case opTilde:
		return "~" + c.version.String()
	default:
		return c.version.String()
	}
}
