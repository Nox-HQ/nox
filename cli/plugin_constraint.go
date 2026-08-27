package main

import (
	"fmt"
	"strconv"
	"strings"
)

// Version constraints in `plugins.required`.
//
// `nox plugin install nox/foo@0.5.0` is accepted syntax, so operators
// reasonably write the same thing in .nox.yaml. Until this existed the whole
// string was matched as a plugin name, so such an entry could never resolve
// and nox reported "is not installed" for a plugin that was installed — with
// the effect that the plugin silently never ran.
//
// Deliberately hand-rolled rather than pulling in a semver library. nox is a
// security scanner with eleven direct dependencies; adding a twelfth to
// compare three integers is a worse trade than the fifty lines below, and a
// supply-chain decision that should not ride along with a bug fix. The
// supported grammar is therefore small and explicit, and anything outside it
// is rejected loudly rather than guessed at.

// parsedVersion is a semantic version reduced to what a constraint can test.
// Pre-release and build metadata are deliberately not modelled: no plugin in
// the registry publishes them, and silently ignoring a suffix would make
// 1.2.3-rc1 satisfy a constraint that means to exclude it.
type parsedVersion struct{ major, minor, patch int }

// parseVersion accepts "1.2.3" or "v1.2.3" and nothing else.
func parseVersion(s string) (parsedVersion, error) {
	bare := strings.TrimPrefix(strings.TrimSpace(s), "v")
	parts := strings.Split(bare, ".")
	if len(parts) != 3 {
		return parsedVersion{}, fmt.Errorf("%q is not a MAJOR.MINOR.PATCH version", s)
	}
	out := make([]int, 3)
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return parsedVersion{}, fmt.Errorf("%q is not a MAJOR.MINOR.PATCH version", s)
		}
		out[i] = n
	}
	return parsedVersion{out[0], out[1], out[2]}, nil
}

// padVersion fills a partial MAJOR or MAJOR.MINOR out to MAJOR.MINOR.PATCH.
// Anything else is returned untouched, so parseVersion still rejects it.
func padVersion(s string) string {
	bare := strings.TrimSpace(s)
	switch strings.Count(bare, ".") {
	case 0:
		if bare == "" {
			return s
		}
		return bare + ".0.0"
	case 1:
		return bare + ".0"
	}
	return s
}

// compare returns -1, 0 or 1.
func (v parsedVersion) compare(o parsedVersion) int {
	for _, pair := range [][2]int{{v.major, o.major}, {v.minor, o.minor}, {v.patch, o.patch}} {
		switch {
		case pair[0] < pair[1]:
			return -1
		case pair[0] > pair[1]:
			return 1
		}
	}
	return 0
}

// constraintSatisfied reports whether an installed version satisfies a
// constraint from `plugins.required`.
//
// Supported: "*" (any), "1.2.3" (exact), ">=1.2.3", "^1.2.3" (compatible, not
// older), "~1.2.3" (same major and minor, not older).
//
// "^" follows the npm/cargo rule that below 1.0.0 the minor is the
// breaking-change axis, so "^0.2.0" means >=0.2.0 <0.3.0 rather than any
// 0.x. Every plugin in the registry is currently 0.x, so the looser reading
// would apply to all of them: an operator writing "^0.2.0" would silently
// accept 0.9.9, which is the belief-without-enforcement this function exists
// to prevent.
//
// An unsupported constraint is an error, never a silent pass. A constraint
// nobody enforces is worse than no constraint at all: the operator believes a
// version is pinned and it is not.
func constraintSatisfied(constraint, installed string) (bool, error) {
	c := strings.TrimSpace(constraint)
	if c == "" || c == "*" {
		return true, nil
	}

	iv, err := parseVersion(installed)
	if err != nil {
		// A locally built plugin records something like "dev". It cannot be
		// compared, and guessing either way is wrong: claiming it satisfies a
		// pin defeats the pin, and claiming it does not breaks plugin
		// development. Say so instead.
		return false, fmt.Errorf("installed version %q cannot be compared against %q", installed, constraint)
	}

	op, rest := "", c
	for _, prefix := range []string{">=", "^", "~"} {
		if strings.HasPrefix(c, prefix) {
			op, rest = prefix, strings.TrimPrefix(c, prefix)
			break
		}
	}

	// An operator may carry a partial version: the README documents
	// `nox/reachability@>=0.5`, and ">=0.5", "^0.5" and "~0.5" each mean the
	// same as their ".0" form under npm and cargo alike. Filling the missing
	// component is therefore reading the operator's intent, not guessing at
	// it. A *bare* partial ("0.5") stays rejected, because there it is
	// genuinely ambiguous — exactly 0.5.0, or anything in 0.5.x?
	if op != "" {
		rest = padVersion(rest)
	}

	want, err := parseVersion(rest)
	if err != nil {
		return false, fmt.Errorf("constraint %q is not supported (use *, 1.2.3, >=1.2.3, ^1.2.3 or ~1.2.3)", constraint)
	}

	switch op {
	case "":
		return iv.compare(want) == 0, nil
	case ">=":
		return iv.compare(want) >= 0, nil
	case "^":
		if iv.major != want.major || iv.compare(want) < 0 {
			return false, nil
		}
		// Below 1.0.0 the minor is the breaking axis, so ^1.2.3 admits 1.9.9
		// while ^0.2.0 admits 0.2.9 and not 0.3.0. (npm and cargo tighten
		// ^0.0.z to an exact match as well; that tier is left looser here
		// because no plugin in the registry is 0.0.x, and the strict reading
		// would make the constraint unwritable for one if there were.)
		//
		// This matters more here than it would elsewhere: every plugin in the
		// registry is currently 0.x, so reading "^" as "same major" would make
		// it mean "any version at all" for all of them — an operator writing
		// ^0.2.0 would silently accept 0.9.9, which is the
		// belief-without-enforcement this function exists to prevent.
		if want.major == 0 {
			return iv.minor == want.minor, nil
		}
		return true, nil
	case "~":
		return iv.major == want.major && iv.minor == want.minor && iv.compare(want) >= 0, nil
	}
	return false, fmt.Errorf("constraint %q is not supported", constraint)
}
