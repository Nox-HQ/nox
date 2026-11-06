package deps

import (
	"github.com/nox-hq/nox/core/findings"
)

// debianUnimportant is the Debian security tracker's rating for an issue it
// does not consider a vulnerability worth fixing in the release: a
// non-default configuration, a build Debian does not ship, a theoretical
// weakness.
const debianUnimportant = "unimportant"

// applyDistroUrgency carries a distribution's own rating of the advisory onto
// the finding. Debian rates each CVE for its release, and CVSS rates the CVE
// in the abstract: CVE-2016-2781 (coreutils chroot) is CVSS 6.5 and Debian
// "low"; dozens of entries a bookworm image carries are CVSS high and Debian
// "unimportant". An unimportant entry is recorded, as every finding is, and
// moved out of gating severity; any other rating travels as metadata and
// leaves the severity alone, because nox has no better basis than CVSS for
// low against medium.
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
	if urgency == debianUnimportant {
		meta["severity_source"] = "distribution"
		return findings.SeverityInfo, message + " [Debian rates this unimportant for " + wire + "]"
	}
	return sev, message
}
