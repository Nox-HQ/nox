package deps

import (
	"context"
	"fmt"

	"github.com/nox-hq/nox-core/degrade"
)

// readImage reads the software installed in the base image a FROM line
// names (nox-hq/nox#1013). Only a digest names fixed content, so a tag is
// reported as not checked rather than resolved: resolving it would make the
// answer depend on when the scan ran. read is true when the image's contents
// were read, whatever they held.
func (a *Analyzer) readImage(ctx context.Context, dockerfile string, img Package) (pkgs []Package, read bool) {
	ref := img.Name + ":" + img.Version
	if !imageIsPinnedToDigest(img.Version) {
		a.degradations.AddAdvisory(degrade.Lockfile,
			fmt.Sprintf("%s: base image %s is named by a tag, which names no fixed content", dockerfile, ref),
			"the software inside it was NOT checked; pin it by digest (FROM name@sha256:…) for nox to read it")
		return nil, false
	}
	ref = img.Name + "@" + img.Version
	contents, err := a.images.Contents(ctx, img.Name, img.Version)
	if err != nil {
		a.degradations.Add(degrade.Lockfile,
			fmt.Sprintf("%s: base image %s could not be read: %v", dockerfile, ref, err),
			"the software inside it was NOT checked for known vulnerabilities")
		return nil, false
	}
	for _, note := range contents.Notes {
		a.degradations.AddAdvisory(degrade.Lockfile, fmt.Sprintf("%s: base image %s: %s", dockerfile, ref, note),
			"its distribution packages were NOT checked")
	}
	for _, p := range contents.Packages {
		pkgs = append(pkgs, Package{Name: p.Name, Version: p.Version, Ecosystem: p.Ecosystem, Origin: OriginImage})
	}
	return pkgs, true
}

// uncheckedImageRefs leaves out the base images whose contents were read:
// they are checked through what they hold, and the "no OSV ecosystem for
// docker" notice is for the ones that were not.
func uncheckedImageRefs(pkgs []Package) []Package {
	out := make([]Package, 0, len(pkgs))
	for _, p := range pkgs {
		if p.Ecosystem == "docker" && p.Origin == OriginImage {
			continue
		}
		out = append(out, p)
	}
	return out
}

// addImageRemediation: software inside a base image moves when the image
// does. No package-manager command applies to it from this tree.
func addImageRemediation(meta map[string]string, imageRef, pkg, fixVer string) {
	delete(meta, "remediation_command")
	meta["remediation_action"] = "manual"
	meta["remediation_note"] = fmt.Sprintf(
		"%s is inside the base image %s. Move the FROM line to a newer digest whose %s is %s or later; nox fix does not change base images.",
		pkg, imageRef, pkg, fixVer)
}
