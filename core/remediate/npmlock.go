package remediate

import (
	"fmt"
	"strings"

	"github.com/nox-hq/nox/core/npmtree"
)

// heldReason says why the move is not reachable and what to do about it. The
// remedy names the entry to add, so the person does not have to look it up.
func heldReason(a upgradePlan, reach npmtree.Reach) string {
	var b strings.Builder
	if a.major {
		fmt.Fprintf(&b, "The fix (%s) is a new major version, and %s is not a package you list yourself", a.step, a.pkg)
	} else {
		fmt.Fprintf(&b, "The fix (%s) is published on the same major version, but %s is not a package you list yourself", a.step, a.pkg)
	}
	if !reach.Established {
		why := reach.Why
		if why == "" {
			why = "nox could not read this workspace's " + npmtree.LockName(reach.Tool)
		}
		fmt.Fprintf(&b, ", and nox cannot see whether the packages that need it allow the move: %s", why)
	} else {
		fmt.Fprintf(&b, " and %s: the range excludes %s", reach.HoldList(), a.to)
	}
	b.WriteString(", so nox fix apply cannot move it. ")
	fmt.Fprintf(&b, "Either upgrade %s to a release that depends on a fixed %s, or force the version with an entry in package.json: %s",
		reach.Holders(), a.pkg, npmtree.OverrideEntry(reach.Tool, a.pkg, a.to))
	return b.String()
}

// uncertainReason says why nox cannot tell whether the move is reachable, and
// what apply does about it.
func uncertainReason(a upgradePlan, reach npmtree.Reach) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s is not a package you list yourself, and nox cannot tell beforehand whether the packages that need it allow %s: %s. ",
		a.pkg, a.to, reach.Why)
	if a.major {
		fmt.Fprintf(&b, "The fix (%s) is also a new major version. ", a.step)
	}
	fmt.Fprintf(&b, "nox fix apply runs the update and reads the lockfile back: if a parent kept it below %s, it says so, "+
		"and the remedy is upgrading that parent or forcing the version with %s in package.json.",
		a.to, npmtree.OverrideEntry(reach.Tool, a.pkg, a.to))
	return b.String()
}

// upgradePlan is the part of an upgrade the reason needs.
type upgradePlan struct {
	pkg, step, to string
	major         bool
}
