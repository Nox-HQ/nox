package vulnsource

import "strings"

// Version matching lives here, in the package both sides import, for the same
// reason core/evidence owns the definition of CONFIRMED: a mirror and a client
// that each decide for themselves which versions an advisory affects will
// eventually disagree, and the disagreement will look like a vulnerability
// appearing or vanishing rather than like a bug.
//
// The comparison is deliberately conservative. A version that cannot be ordered
// is never treated as affected, because guessing would mean picking a fix at
// random — and a scanner that recommends a downgrade is worse than one that
// says nothing.

// Interval is one contiguous affected range from an advisory: versions from
// Introduced (inclusive) up to Fixed (exclusive), or through LastAffected
// (inclusive). Fixed is empty when the interval names no fix — an unfixed
// release branch.
type Interval struct {
	Introduced   string
	Fixed        string
	LastAffected string
}

// Covers reports whether the installed version falls inside the interval.
func (iv Interval) Covers(installed string) bool {
	if !ComparableVersion(installed) {
		return false
	}
	// "0" is OSV's "since the beginning"; comparing against it directly would
	// exclude prereleases of 0.0.0, which sort below it.
	if iv.Introduced != "" && iv.Introduced != "0" {
		if !ComparableVersion(iv.Introduced) || CompareVersions(installed, iv.Introduced) < 0 {
			return false
		}
	}
	switch {
	case iv.Fixed != "":
		return ComparableVersion(iv.Fixed) && CompareVersions(installed, iv.Fixed) < 0
	case iv.LastAffected != "":
		return ComparableVersion(iv.LastAffected) && CompareVersions(installed, iv.LastAffected) <= 0
	}
	return true // introduced with no upper bound: still unfixed
}

// ComparableVersion reports whether v carries an ordering CompareVersions can
// be trusted with. A value whose leading segment is not numeric — "latest",
// "unknown", a git SHA, an empty string — does not.
func ComparableVersion(v string) bool {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	lead, _, _ := strings.Cut(v, ".")
	lead, _, _ = strings.Cut(lead, "-")
	lead, _, _ = strings.Cut(lead, "+")
	if lead == "" {
		return false
	}
	for _, r := range lead {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// CompareVersions orders two semver-shaped versions, returning -1, 0, or 1.
// A release sorts above its own prereleases.
func CompareVersions(a, b string) int {
	an, apre := splitVersion(a)
	bn, bpre := splitVersion(b)

	for i := range 3 {
		if an[i] != bn[i] {
			if an[i] < bn[i] {
				return -1
			}
			return 1
		}
	}

	switch {
	case apre == bpre:
		return 0
	case apre == "": // release beats prerelease
		return 1
	case bpre == "":
		return -1
	case apre < bpre:
		return -1
	default:
		return 1
	}
}

// splitVersion breaks "v1.2.3-rc1" into its numeric triple and prerelease.
func splitVersion(v string) (nums [3]int, prerelease string) {
	v = strings.TrimPrefix(v, "v")
	if i := strings.Index(v, "+"); i >= 0 { // build metadata is not ordered
		v = v[:i]
	}
	core, pre, _ := strings.Cut(v, "-")
	for i, part := range strings.SplitN(core, ".", 3) {
		if i > 2 {
			break
		}
		n := 0
		for _, r := range part {
			if r < '0' || r > '9' {
				n = 0
				break
			}
			n = n*10 + int(r-'0')
		}
		nums[i] = n
	}
	return nums, pre
}

// AffectedIntervals expands the advisory's affected entries for the given
// package into flat intervals.
//
// OSV expresses a package's affected versions either as several `affected`
// entries with one range each, or as one range with several introduced/fixed
// pairs. Both mean the same thing and both occur in real advisories, so both
// are flattened here.
//
// wireEcosystem is the ecosystem name as it appears inside the advisory
// (OSV's own vocabulary, e.g. "Go", "npm", "PyPI"). Callers holding a nox
// ecosystem name must map it first; this package deliberately does not know
// that mapping, which belongs to whichever wire protocol produced the record.
func (r *Record) AffectedIntervals(pkgName, wireEcosystem string) []Interval {
	want := strings.ToLower(pkgName)
	var out []Interval

	for _, aff := range r.Affected {
		if !strings.EqualFold(aff.Package.Name, want) {
			continue
		}
		if aff.Package.Ecosystem != "" && wireEcosystem != "" &&
			!strings.EqualFold(aff.Package.Ecosystem, wireEcosystem) {
			continue
		}
		for _, rng := range aff.Ranges {
			cur := Interval{}
			open := false
			for _, e := range rng.Events {
				switch {
				case e.Introduced != "":
					if open {
						out = append(out, cur)
					}
					cur, open = Interval{Introduced: e.Introduced}, true
				case e.Fixed != "":
					cur.Fixed = e.Fixed
					out = append(out, cur)
					cur, open = Interval{}, false
				case e.LastAffected != "":
					cur.LastAffected = e.LastAffected
					out = append(out, cur)
					cur, open = Interval{}, false
				}
			}
			if open {
				out = append(out, cur)
			}
		}
	}
	return out
}

// Retracted reports whether the source database has withdrawn the advisory.
func (r *Record) Retracted() bool { return r.Withdrawn != "" }

// Affects reports whether the advisory covers pkgName at the given version.
//
// This is what a source holding a local corpus must answer, and what a source
// proxying a remote API gets answered for it. Both must agree, or the same
// package version is vulnerable according to one and clean according to the
// other.
func (r *Record) Affects(pkgName, wireEcosystem, version string) bool {
	// A withdrawn advisory affects nothing, whatever its ranges still say.
	if r.Retracted() {
		return false
	}
	for _, iv := range r.AffectedIntervals(pkgName, wireEcosystem) {
		if iv.Covers(version) {
			return true
		}
	}
	return false
}

// FixedVersion returns the version the installed one must move to in order to
// clear the advisory, or "" when that cannot be established.
//
// An advisory covering a package with maintained release branches names one fix
// per branch. Reporting any fix other than the one for the branch in use is not
// a cosmetic mislabel: the fix for an older branch is a *lower* version than
// what is installed, so the remediation reads as a downgrade — to something
// plausibly vulnerable to a different advisory, and certainly a functional
// regression. So the interval containing the installed version selects the fix,
// not the order the advisory happens to list its ranges in.
//
// "" is returned whenever no interval contains the installed version: outside
// the ranges, on a branch with no fix yet, or with a version string that cannot
// be ordered. That is a genuine "we do not know", and any answer invented to
// fill it would reintroduce the defect in a new form.
func (r *Record) FixedVersion(pkgName, wireEcosystem, installed string) string {
	intervals := r.AffectedIntervals(pkgName, wireEcosystem)

	// A single interval leaves nothing to select between, and its bounds are
	// the ones the source already matched the installed version against.
	if len(intervals) == 1 {
		return intervals[0].Fixed
	}

	best := ""
	for _, iv := range intervals {
		if iv.Fixed == "" || !iv.Covers(installed) {
			continue
		}
		// Overlapping intervals are malformed data, but if they occur the
		// smallest upgrade that clears the advisory is the honest answer.
		if best == "" || CompareVersions(iv.Fixed, best) < 0 {
			best = iv.Fixed
		}
	}
	return best
}
