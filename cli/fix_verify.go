package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/nox-hq/nox/core/fix"
)

// regression is a package that ended up lower than where nox found it.
type regression struct {
	pkg    string
	from   string
	actual string
}

// verifyNoRegression re-reads the manifests after the upgrades were applied and
// checks that nothing moved backwards.
//
// Planning correctly is not the same as landing correctly. `go get` resolves
// against the whole module graph, so a constraint elsewhere can pull a package
// below the requested version; a package manager can also simply do something
// other than what was asked. Either way the result is a "chore(security)" diff
// that lowers a dependency, which is how felixgeelhaar/specular#51 reached a
// reviewer.
//
// This is the postcondition to the planner's precondition: planUpgrades refuses
// to *ask* for a downgrade, and this refuses to *ship* one. Both are needed —
// the planner cannot see what the package manager actually did.
//
// Returns the regressions found and the packages it could not check. Those are
// reported separately and deliberately: an ecosystem whose manifest nox cannot
// yet read is unverified, which is not the same as verified clean, and saying
// so is the difference between a guarantee and a hope.
func verifyNoRegression(manifestRoot string, actions []upgradeAction) (bad []regression, unchecked []string) {
	for _, a := range actions {
		actual, ok := installedVersion(manifestRoot, a)
		if !ok {
			unchecked = append(unchecked, fmt.Sprintf("%s [%s]", a.pkg, a.ecosystem))
			continue
		}
		// Only flag a genuine backwards move. Landing above the requested
		// target is fine — a newer version already satisfies the advisory.
		if a.fromVer != "" && !fix.IsUpgrade(a.fromVer, actual) && actual != a.fromVer {
			bad = append(bad, regression{pkg: a.pkg, from: a.fromVer, actual: actual})
		}
	}
	return bad, unchecked
}

// installedVersion reads a package's resolved version from the manifest after
// an upgrade. Reports ok=false for ecosystems it cannot read rather than
// guessing — see verifyNoRegression on why that distinction is kept.
func installedVersion(manifestRoot string, a upgradeAction) (string, bool) {
	if a.ecosystem != "go" {
		// Other ecosystems resolve through lockfiles with their own formats;
		// until each is parsed, they are reported as unchecked.
		return "", false
	}
	// The finding's own module, not the project root: a monorepo has a go.mod
	// per module, and reading the wrong one reports every package unchecked.
	dir, err := workdirFor(manifestRoot, a)
	if err != nil {
		return "", false
	}
	return goModVersion(filepath.Join(dir, "go.mod"), a.pkg)
}

// goModVersion finds a module's version in a go.mod require line.
func goModVersion(path, module string) (string, bool) {
	f, err := os.Open(path) // #nosec G304 -- path derives from the caller's manifest root
	if err != nil {
		return "", false
	}
	defer func() { _ = f.Close() }()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		// "require example.com/m v1.2.3" or, inside a block, "example.com/m v1.2.3"
		line = strings.TrimPrefix(line, "require ")
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != module {
			continue
		}
		return strings.TrimPrefix(fields[1], "v"), true
	}
	return "", false
}
