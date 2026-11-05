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
		fmt.Fprintf(&b, " and nox could not read this workspace's %s to see whether the packages that need it allow the move", npmtree.LockName(reach.Tool))
	} else {
		fmt.Fprintf(&b, " and %s: the range excludes %s", reach.HoldList(), a.to)
	}
	b.WriteString(", so nox fix apply cannot move it. ")
	fmt.Fprintf(&b, "Either upgrade %s to a release that depends on a fixed %s, or force the version with an entry in package.json: %s",
		reach.Holders(), a.pkg, npmtree.OverrideEntry(reach.Tool, a.pkg, a.to))
	return b.String()
}

// upgradePlan is the part of an upgrade the reason needs.
type upgradePlan struct {
	pkg, step, to string
	major         bool
}
