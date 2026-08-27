package deps

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/nox-hq/nox-core/vulnsource"
	"github.com/nox-hq/nox-core/vulnsource/osv"
	"github.com/nox-hq/nox/core/findings"
)

// The OSV wire protocol — batching, ecosystem filtering, the query-then-hydrate
// two-step, and its failure modes — lives in core/vulnsource/osv behind the
// vulnsource.Source interface. What stays here is the semantic layer applied to
// whatever a source returns: which version clears an advisory, what severity a
// score maps to, and how an operator upgrades.
//
// The record types are aliases rather than conversions. vulnsource.Record is
// OSV-wire-shaped by design (see the vulnsource package docs), so a conversion
// layer here would be a no-op that could only introduce drift.
type (
	osvVuln              = vulnsource.Record
	osvSeverity          = vulnsource.Severity
	osvPackage           = vulnsource.Package
	osvAffected          = vulnsource.Affected
	osvRange             = vulnsource.Range
	osvEvent             = vulnsource.Event
	osvImport            = vulnsource.Import
	osvEcosystemSpecific = vulnsource.EcosystemSpecific
	osvDatabaseSpecific  = vulnsource.DatabaseSpecific

	osvBatchRequest  = osv.BatchRequest
	osvBatchResponse = osv.BatchResponse
	osvBatchResult   = osv.BatchResult
)

// The interval arithmetic lives in core/vulnsource, imported by both this
// analyzer and any source holding a local corpus, so the two cannot come to
// disagree about which versions an advisory affects. What remains here is the
// nox-ecosystem-to-OSV-vocabulary mapping, which is a wire concern.

func fixedVersion(vuln *osvVuln, pkgName, ecosystem, installed string) string {
	return vuln.FixedVersion(pkgName, ecosystemToOSV(ecosystem), installed)
}

// mapOSVSeverity converts OSV severity entries to a nox Severity.
// It looks for a CVSS_V3 score first, then falls back to CVSS_V2, then to the
// source database's coarse severity label.
//
// The label matters because CVSS v4 vectors score by a different and
// substantially more complex algorithm that cvssToSeverity does not attempt.
// Without the fallback, an advisory publishing only a v4 vector — an
// increasingly common case — silently collapsed to medium regardless of how
// severe it actually was. SeverityMedium now means a genuine "unknown".
func mapOSVSeverity(sev []osvSeverity, dbSpecific osvDatabaseSpecific) findings.Severity {
	// A computable CVSS base score is the most precise signal, so it wins when
	// one is available. Note the score must be PARSED, not merely present: a
	// CVSS v2 vector matches the type check but cannot be scored, and returning
	// on it discarded an accurate database label in favour of cvssToSeverity's
	// medium default.
	for _, s := range sev {
		if s.Type != "CVSS_V3" && s.Type != "CVSS_V2" {
			continue
		}
		if score, ok := cvssBaseScore(s.Score); ok {
			return scoreToSeverity(score)
		}
	}

	// No score we could compute — fall back to the source database's coarse
	// label. This is the only severity signal for CVSS v4-only advisories.
	if s, ok := severityFromLabel(dbSpecific.Severity); ok {
		return s
	}

	// Genuinely unknown.
	return findings.SeverityMedium
}

// severityFromLabel maps a coarse textual severity label to a nox Severity.
// GitHub advisories say "MODERATE" where most other sources say "MEDIUM".
func severityFromLabel(label string) (findings.Severity, bool) {
	switch strings.ToUpper(strings.TrimSpace(label)) {
	case "CRITICAL":
		return findings.SeverityCritical, true
	case "HIGH":
		return findings.SeverityHigh, true
	case "MODERATE", "MEDIUM":
		return findings.SeverityMedium, true
	case "LOW":
		return findings.SeverityLow, true
	default:
		return "", false
	}
}

// cvssBaseScore returns the CVSS base score for an OSV severity value, which
// is published either as a bare number ("9.8") or as a vector string.
//
// The bool reports whether a score could be DERIVED, which callers must
// distinguish from a low score. CVSS v2 and v4 vectors match OSV's type field
// but use scoring algorithms this does not implement; conflating "cannot
// compute" with "scored medium" discarded accurate severity labels.
func cvssBaseScore(score string) (float64, bool) {
	// A bare number, as some databases publish.
	if f, err := strconv.ParseFloat(score, 64); err == nil {
		return f, true
	}

	// OSV publishes CVSS as a vector string, e.g.
	// "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H". The base score is not
	// embedded in it, but it is fully determined by it, so compute it.
	return cvssV3BaseScore(score)
}

// scoreToSeverity buckets a CVSS base score using the standard qualitative
// severity rating scale.
func scoreToSeverity(f float64) findings.Severity {
	switch {
	case f >= 9.0:
		return findings.SeverityCritical
	case f >= 7.0:
		return findings.SeverityHigh
	case f >= 4.0:
		return findings.SeverityMedium
	case f >= 0.1:
		return findings.SeverityLow
	default:
		return findings.SeverityInfo
	}
}

// cvssToSeverity converts a CVSS vector string or numeric score to a Severity,
// falling back to medium when no score can be derived.
func cvssToSeverity(score string) findings.Severity {
	f, ok := cvssBaseScore(score)
	if !ok {
		return findings.SeverityMedium
	}
	return scoreToSeverity(f)
}

// upgradeCommand returns the canonical one-liner an operator can run to
// upgrade a package to its fixed version. Returns "" for ecosystems we
// don't have a templated command for (the operator can still see fixed_in).
func upgradeCommand(ecosystem, pkg, fixedVer string) string {
	switch ecosystem {
	case "go":
		return fmt.Sprintf("go get %s@v%s", pkg, strings.TrimPrefix(fixedVer, "v"))
	case "npm":
		return fmt.Sprintf("npm install %s@%s", pkg, fixedVer)
	case "pypi":
		return fmt.Sprintf("pip install '%s>=%s'", pkg, fixedVer)
	case "rubygems":
		return fmt.Sprintf("bundle update %s --conservative", pkg)
	case "cargo":
		return fmt.Sprintf("cargo update -p %s --precise %s", pkg, fixedVer)
	case "maven", "gradle":
		return fmt.Sprintf("upgrade %s to %s in your build file", pkg, fixedVer)
	case "nuget":
		return fmt.Sprintf("dotnet add package %s --version %s", pkg, fixedVer)
	default:
		return ""
	}
}

// osvEcosystem reports the OSV ecosystem string for a nox ecosystem name, and
// whether OSV recognises it at all. Delegated to the wire implementation, which
// owns the vocabulary.
func osvEcosystem(eco string) (string, bool) { return osv.Ecosystem(eco) }

// ecosystemToOSV maps a nox ecosystem name to OSV's, returning the input
// unchanged for ecosystems OSV does not recognise. Used only for best-effort
// matching within already-returned records, never to issue queries.
func ecosystemToOSV(eco string) string { return osv.EcosystemName(eco) }
