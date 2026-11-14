package deps

import (
	"fmt"
	"strings"

	"github.com/nox-hq/nox/core/findings"
)

// notWorthFixing are the distributions' ratings for an issue they do not
// consider a vulnerability worth fixing in the release (a non-default
// configuration, a build they do not ship, a theoretical weakness): Debian's
// "unimportant" and Ubuntu's "negligible".
var notWorthFixing = map[string]string{"unimportant": "Debian", "negligible": "Ubuntu"}

// applyDistroUrgency carries a distribution's own rating of the advisory onto
// the finding. Debian rates each CVE for its release, and CVSS rates the CVE
// in the abstract: CVE-2016-2781 (coreutils chroot) is CVSS 6.5 and Debian
// "low"; dozens of entries a bookworm image carries are CVSS high and Debian
// "unimportant". Such an entry (Ubuntu's word is "negligible") is recorded,
// as every finding is, and moved out of gating severity; any other rating
// travels as metadata and leaves the severity alone, because nox has no
// better basis than CVSS for low against medium.
func applyDistroUrgency(meta map[string]string, ov *osvVuln, pkg Package, sev findings.Severity, message string) (newSev findings.Severity, newMessage string) {
	wire, ok := osvEcosystem(pkg.Ecosystem)
	if !ok {
		return sev, message
	}
	urgency := ov.DistroUrgency(pkg.Name, wire)
	if urgency == "" {
		return sev, message
	}
	meta["distro_urgency"] = urgency
	if distro, ok := notWorthFixing[urgency]; ok {
		meta["severity_source"] = "distribution"
		if sev != findings.SeverityInfo {
			meta["original_severity"] = string(sev)
		}
		return findings.SeverityInfo, message + " [" + distro + " rates this " + urgency + " for " + wire + "]"
	}
	return sev, message
}

// gateOnlyFixable records an image advisory with no fix released at info,
// keeping its severity in original_severity. Software inside a base image is
// fixed by its distribution or upstream, not by this repository; an advisory
// nobody can install a fix for yet is worth knowing and not worth failing a
// build on, and gating on it teaches people to turn image checking off. An
// advisory with a fix keeps its severity and gates. Packages from the tree
// are untouched.
func gateOnlyFixable(meta map[string]string, pkg Package, sev findings.Severity, message string) (newSev findings.Severity, newMessage string) {
	if pkg.Origin != OriginImage || meta["fixed_in"] != "" || sev == findings.SeverityInfo {
		return sev, message
	}
	meta["original_severity"] = string(sev)
	meta["severity_source"] = "no_fix_available"
	return findings.SeverityInfo, message + " [no fix released yet for the image's package: recorded at info, not gating]"
}

// headline opens a dependency finding's message: what it is, which package,
// and the advisory's own summary. Distribution advisories often have none, and
// the message says so instead of leaving a colon in front of nothing.
func headline(lead, name, version, summary string) string {
	subject := fmt.Sprintf("%s in %s@%s", lead, name, version)
	if summary = strings.TrimSpace(summary); summary == "" {
		return subject + " (the advisory carries no summary)"
	}
	return subject + ": " + summary
}

// demoteBuildStageOnly records an advisory for software in a build-only stage
// at info, keeping its severity in original_severity. The stage's image is
// where the artifact is built, not what ships: neither its packages nor its
// files reach the final image (buildOnlyStages decides that, and anything it
// cannot resolve counts as shipped). This is the treatment a Go advisory for a
// package the build does not link has had since 1.58.0 — recorded, not
// dropped, and not gating. The stage is named, because a build run with
// --target publishes that stage instead, and then the finding is about what
// ships.
func demoteBuildStageOnly(meta map[string]string, stage string, sev findings.Severity) (newSev findings.Severity, note string) {
	if stage == "" {
		return sev, ""
	}
	meta["image_stage"] = stage
	meta["image_stage_shipped"] = "false"
	if sev == findings.SeverityInfo {
		return sev, ""
	}
	if meta["original_severity"] == "" {
		meta["original_severity"] = string(sev)
	}
	meta["severity_source"] = "build_stage_only"
	return findings.SeverityInfo, fmt.Sprintf(
		" [only in build stage %q, which the final image is not built on and copies no system files from: recorded at info, not gating; if you build with --target %s, it is what ships]",
		stage, stage)
}

// stageAt is buildOnly[i], or "" past its end.
func stageAt(buildOnly []string, i int) string {
	if i < len(buildOnly) {
		return buildOnly[i]
	}
	return ""
}
