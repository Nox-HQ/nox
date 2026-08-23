// Package fix is the single source of truth for planning dependency-upgrade
// remediations from VULN-001 findings.
//
// It exists because two entry points — the `nox fix` CLI and the MCP `fix_plan`
// tool — both need to decide "which packages should move, to what version" from
// the same findings, and for a supply-chain remediation surface those two
// answers must be identical. They were not: the MCP copy had drifted, missing
// the CLI's guard against downgrades and prereleases, aggregating advisories
// differently, and disagreeing on which ecosystems nox can actually drive. A
// planner that shows an agent a downgrade the CLI would refuse to apply is
// actively dangerous, so the plan and the applier now share this one function.
//
// This package is pure: no I/O, no execution. It decides the plan; the CLI's
// applier runs it.
package fix

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

// IsUpgrade reports whether moving from -> to is a genuine forward move that
// nox should apply.
//
// Three refusals, each one a bug seen in production:
//
//   - to <= from. An advisory's fixed_in is the version that closed THAT
//     advisory, not the newest safe version; the lowest is routinely below what
//     is already installed, and adopting it downgrades the package and can
//     reintroduce advisories the repo had already cleared.
//   - a prerelease target when the install is stable. A development tag is a
//     real upstream version but not one production code should start tracking
//     because a scanner suggested it.
//   - a non-empty installed version nox cannot order. Without an ordering there
//     is no way to know the move is forward, and a security-titled change is the
//     worst place to guess.
//
// An ABSENT installed version is treated differently from an unparseable one:
// some scanners do not populate it, and refusing there would silently stop
// remediating whole ecosystems. Absence is not evidence of a downgrade, so the
// direction check is skipped — but the prerelease guard still applies, because
// it needs no ordering.
func IsUpgrade(from, to string) bool {
	t := parseVersion(to)
	if !t.ok {
		return false
	}
	f := parseVersion(from)

	if t.prerelease && !f.prerelease {
		return false
	}
	if strings.TrimSpace(from) == "" {
		return true
	}
	if !f.ok {
		return false
	}
	return compareVersions(t, f) > 0
}

// BestFix picks the highest of several candidate fix versions.
//
// Advisories are independent: each names the version that closed it. Applying
// them one at a time lets the last one win by accident, which is order, not
// safety. The highest fix clears every advisory below it in one move.
func BestFix(candidates []string) string {
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

// IsMajorBump reports whether the fix version's leading numeric component
// differs from the current version's. A non-numeric or empty leading segment is
// treated as same-major, to be conservative: nox does not skip an upgrade over
// a boundary it cannot actually see.
func IsMajorBump(from, to string) bool {
	if from == "" || to == "" {
		return false
	}
	return majorOf(from) != majorOf(to)
}

// majorOf returns the leading numeric segment of a version ("v1.2.3" -> "1").
func majorOf(version string) string {
	v := strings.TrimPrefix(version, "v")
	if i := strings.IndexByte(v, '.'); i >= 0 {
		v = v[:i]
	}
	return v
}
