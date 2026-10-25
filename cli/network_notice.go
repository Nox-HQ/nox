package main

import (
	"fmt"

	nox "github.com/nox-hq/nox/core"
)

// networkNotice says, once, what a default scan sent off the machine and how to
// stop it. The default scan asks NOX Intelligence about every dependency, and
// the only line it used to print about the network was the --offline guarantee,
// so a developer who never read the docs had no way to learn that package names
// and versions had left the machine.
//
// It lives in the CLI adapter because it is wording about a decision the core
// already took: the condition mirrors core's vulnLookupEnabled (not offline, not
// --no-osv, not scan.osv.disabled, the deps scope ran) and adds "there was at
// least one dependency", so a project with no lockfile is not told about a
// request that was never made. It returns "" when nothing was sent.
func networkNotice(cfg *nox.ScanConfig, offline, noOSV, depsScanned bool, depCount int) string {
	if offline || noOSV || cfg.Scan.OSV.Disabled || !depsScanned || depCount == 0 {
		return ""
	}
	osv := cfg.Scan.OSV.ReferenceBaseURL()
	if endpoint := cfg.Scan.Intelligence.ResolvedEndpoint(); endpoint != "" {
		return fmt.Sprintf("[network] dependency lookup: the ecosystem, name and version of %d dependencies "+
			"were sent to %s and checked against %s (answers already cached on this machine are not "+
			"asked again). Source code, file paths and findings were not sent. "+
			"Opt out: scan.intelligence.disabled: true in .nox.yaml asks %s directly instead; "+
			"--offline or scan.osv.disabled: true makes no network request. See docs/intelligence.md.",
			depCount, endpoint, osv, osv)
	}
	return fmt.Sprintf("[network] dependency lookup: the ecosystem, name and version of %d dependencies "+
		"were sent to %s (answers already cached on this machine are not asked again). "+
		"Source code, file paths and findings were not sent. "+
		"Opt out: --offline or scan.osv.disabled: true makes no network request.", depCount, osv)
}
