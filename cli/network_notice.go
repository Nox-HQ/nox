package main

import (
	"fmt"
	"strings"

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

// mavenNetworkNotice says that Maven parent and BOM coordinates were sent to
// fetch their POMs. It is a separate line because it is a separate request with
// a separate reason, and a scan of a project with no external parent never
// makes it. It returns "" when none were sent.
func mavenNetworkNotice(cfg *nox.ScanConfig, requested int) string {
	if requested == 0 {
		return ""
	}
	return fmt.Sprintf("[network] Maven resolution: the group, artifact and version of %d published parent or BOM POM(s) "+
		"the repository does not contain were sent to %s, which fetched them from Maven Central so dependency versions "+
		"managed there could be resolved. Same opt-outs as the dependency lookup.",
		requested, cfg.Scan.Intelligence.ResolvedEndpoint())
}

// imageNetworkNotice names the hosts a scan pulled base images from. A pull
// goes to the registry, to the token service the registry names and to the
// storage host it redirects to, none of which is the advisory source, so the
// dependency notice says nothing about them. hosts is what the image client
// recorded; it is empty, and nothing is printed, when the cache answered.
func imageNetworkNotice(hosts []string) string {
	if len(hosts) == 0 {
		return ""
	}
	return fmt.Sprintf("[network] base images: the digest-pinned images named in Dockerfiles were pulled anonymously from %s "+
		"(image name and digest sent; layers already cached on this machine are not fetched again). "+
		"Nothing from the repository was sent. "+
		"Opt out: scan.images.enabled: false in .nox.yaml reads no image; "+
		"--offline or scan.osv.disabled: true reads cached images only.", strings.Join(hosts, ", "))
}

// goModulesNetworkNotice says that the go command was let onto the network.
// nox asks it which packages the build links, so a Go advisory for a package
// the build does not link is not reported as if it applied; when the module
// cache lacks a module the build needs, the go command fetches it the way
// `go build` does. sources is where it was allowed to fetch from; it is empty,
// and nothing is printed, when the module cache answered.
func goModulesNetworkNotice(sources []string) string {
	if len(sources) == 0 {
		return ""
	}
	named := make([]string, len(sources))
	for i, s := range sources {
		if s == "direct" {
			s = "the modules' own source hosts"
		}
		named[i] = s
	}
	return fmt.Sprintf("[network] Go modules: the module cache did not hold every module this build needs, so the go command "+
		"fetched the missing ones as `go build` does, through GOPROXY (%s). Module paths and versions from go.mod were sent; "+
		"set GOPRIVATE for module paths that must not reach a public proxy. "+
		"Opt out: GOPROXY=off keeps the go command off the network, and Go advisories are then not narrowed to the packages "+
		"the build links; --offline or scan.osv.disabled: true makes no network request.", strings.Join(named, ", then "))
}
