package main

import (
	"strconv"
	"strings"
)

// parsedVersion is the comparable part of a version string: its numeric
// release components plus whether a prerelease suffix was present.
type parsedVersion struct {
	nums       []int
	prerelease bool
	ok         bool
}

// parseVersion reads a dotted numeric version, tolerating a leading "v" and a
// trailing prerelease or build suffix.
//
// Deliberately strict about the numeric core: a version whose leading segment
// is not a number (a branch name, a date stamp, a pseudo-version) returns
// ok=false, and callers skip it. Guessing at an ordering nox cannot actually
// determine is how a "fix" ends up moving a dependency somewhere nobody asked
// for.
func parseVersion(s string) parsedVersion {
	s = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(s), "v"))
	if s == "" {
		return parsedVersion{}
	}

	// Split off prerelease ("-dev", "-rc.1") and build ("+meta") metadata.
	core := s
	pre := false
	if i := strings.IndexAny(core, "-+"); i >= 0 {
		pre = core[i] == '-'
		core = core[:i]
	}

	parts := strings.Split(core, ".")
	nums := make([]int, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return parsedVersion{}
		}
		nums = append(nums, n)
	}
	if len(nums) == 0 {
		return parsedVersion{}
	}
	return parsedVersion{nums: nums, prerelease: pre, ok: true}
}

// compareVersions returns -1, 0 or 1 comparing a to b by numeric components,
// then treating a prerelease as lower than the release it precedes (1.2.0-dev
// < 1.2.0), per semver.
func compareVersions(a, b parsedVersion) int {
	n := len(a.nums)
	if len(b.nums) > n {
		n = len(b.nums)
	}
	for i := 0; i < n; i++ {
		var x, y int
		if i < len(a.nums) {
			x = a.nums[i]
		}
		if i < len(b.nums) {
			y = b.nums[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	switch {
	case a.prerelease && !b.prerelease:
		return -1
	case !a.prerelease && b.prerelease:
		return 1
	}
	return 0
}

// isUpgrade reports whether moving from -> to is a genuine forward move that
// nox should apply.
//
// Three refusals, each one a bug seen in production:
//
//   - to <= from. An advisory's fixed_in is the version that closed THAT
//     advisory, not the newest safe version. A package with several advisories
//     yields several fixed_in values, and the lowest is routinely below what is
//     already installed — felixgeelhaar/specular#51 downgraded
//     golang.org/x/crypto 0.54.0 -> 0.51.0 that way and reintroduced nine
//     critical advisories into a repo that scanned clean.
//   - a prerelease target when the install is stable.
//     felixgeelhaar/orbita#49 pinned google.golang.org/grpc to v1.81.0-dev, a
//     real upstream tag but a development marker. Production code should not
//     start tracking one because a scanner suggested it.
//   - a non-empty installed version nox cannot order. Without an ordering
//     there is no way to know the move is forward, and a security-titled PR is
//     the worst place to guess.
//
// An ABSENT installed version is treated differently from an unparseable one.
// Some scanners do not populate it at all; refusing there would silently stop
// remediating whole ecosystems, which is its own quiet failure. Absence is not
// evidence of a downgrade, so the direction check is skipped — but the
// prerelease guard still applies, because that one needs no ordering.
func isUpgrade(from, to string) bool {
	t := parseVersion(to)
	if !t.ok {
		return false
	}

	f := parseVersion(from)

	// Never adopt a prerelease from a stable release. Decidable without
	// knowing the installed version, so it is checked first and always.
	if t.prerelease && !f.prerelease {
		return false
	}

	// No installed version reported: apply, and count on the prerelease guard
	// above. Refusing here would drop coverage for scanners that omit it.
	if strings.TrimSpace(from) == "" {
		return true
	}

	// A value we cannot order is not a licence to guess.
	if !f.ok {
		return false
	}

	return compareVersions(t, f) > 0
}

// bestFix picks the highest of several candidate fix versions.
//
// Advisories are independent: each names the version that closed it. Applying
// them one at a time lets the last one win by accident, which is order, not
// safety. The highest fix clears every advisory below it in one move.
func bestFix(candidates []string) string {
	best := ""
	var bestParsed parsedVersion
	for _, c := range candidates {
		p := parseVersion(c)
		if !p.ok {
			continue
		}
		if best == "" || compareVersions(p, bestParsed) > 0 {
			best, bestParsed = c, p
		}
	}
	return best
}
