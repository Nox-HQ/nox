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
// Supported: "*" (any), "1.2.3" (exact), ">=1.2.3", "^1.2.3" (same major, not
// older), "~1.2.3" (same major and minor, not older).
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
		return iv.major == want.major && iv.compare(want) >= 0, nil
	case "~":
		return iv.major == want.major && iv.minor == want.minor && iv.compare(want) >= 0, nil
	}
	return false, fmt.Errorf("constraint %q is not supported", constraint)
}
