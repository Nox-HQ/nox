package findings

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
)

// FingerprintVersion controls which fingerprint algorithm runs. Default is
// V2 (path + content + rule_id, with path normalised — backslash →
// forward-slash, leading `./` stripped, `..` collapsed). V2 drops the line
// number so trivial diffs — import shifts, gofmt, comment edits — don't
// invalidate baselined findings. V2 does NOT resolve a git root; producing a
// stable repo-root-relative path is the caller's responsibility (the scan loop
// already does this when invoked from a git working tree).
//
// V1 (line + path + content + rule_id) is the original algorithm, retained for
// consumers with existing V1 baselines. Pin it via:
//
//   - environment: NOX_FINGERPRINT_VERSION=1
//   - Go API:      findings.SetFingerprintVersion(1)
//   - CLI flag:    nox scan --fingerprint-version 1
//
// Upgrading from a nox that defaulted to V1: existing baseline / VEX entries
// carry V1 fingerprints and will no longer match. Run `nox baseline migrate`
// (re-fingerprints in place) or regenerate the baseline with
// `nox baseline write`. See docs/migration-fingerprint-v2.md.
type FingerprintVersion int32

const (
	// FingerprintV1 — sha256(rule_id || file_path || start_line || content).
	// Original algorithm; stable across releases ≤ v0.10.0.
	FingerprintV1 FingerprintVersion = 1
	// FingerprintV2 — sha256(rule_id || normalised_file_path || content).
	// Drops start_line; normalises file_path to forward-slash and strips
	// `./`. Tolerates code shifts in line numbers and scan-root mismatches
	// between local (`nox scan ./http`) and CI (`nox scan .`).
	FingerprintV2 FingerprintVersion = 2

	// DefaultFingerprintVersion is the version applied when no explicit
	// configuration is set. V2 (line-independent) as of v1.3.0; pin V1 via
	// NOX_FINGERPRINT_VERSION=1 / --fingerprint-version 1 for legacy baselines.
	DefaultFingerprintVersion = FingerprintV2
)

// fingerprintVersion holds the active algorithm. Stored as int32 so the
// SetFingerprintVersion / fingerprintVersionFromEnv writers can use
// atomics without a mutex.
var fingerprintVersion atomic.Int32

func init() {
	fingerprintVersion.Store(int32(versionFromEnv(DefaultFingerprintVersion)))
}

// SetFingerprintVersion overrides the active algorithm. Callers
// typically wire this from a CLI flag at startup; tests can use it to
// pin behaviour. Pass an unknown version to fall back to the default.
func SetFingerprintVersion(v FingerprintVersion) {
	if v != FingerprintV1 && v != FingerprintV2 {
		v = DefaultFingerprintVersion
	}
	fingerprintVersion.Store(int32(v))
}

// GetFingerprintVersion returns the active algorithm.
func GetFingerprintVersion() FingerprintVersion {
	return FingerprintVersion(fingerprintVersion.Load())
}

// versionFromEnv reads NOX_FINGERPRINT_VERSION; returns fallback when
// unset or unparseable. Exposed for tests.
func versionFromEnv(fallback FingerprintVersion) FingerprintVersion {
	switch os.Getenv("NOX_FINGERPRINT_VERSION") {
	case "1", "v1":
		return FingerprintV1
	case "2", "v2":
		return FingerprintV2
	default:
		return fallback
	}
}

// ComputeFingerprint produces a deterministic SHA-256 hex digest from
// the inputs. The exact ingredients depend on the active
// FingerprintVersion (see the type doc). Identical (rule_id, location,
// content) inputs always produce the same fingerprint within a single
// algorithm version; switching versions invalidates prior digests.
func ComputeFingerprint(ruleID string, loc Location, content string) string {
	return ComputeFingerprintWith(ruleID, loc, content, GetFingerprintVersion())
}

// ComputeFingerprintWith is the explicit-version variant of
// ComputeFingerprint. Use it when a single process needs to mix
// algorithms (e.g. during baseline migration).
func ComputeFingerprintWith(ruleID string, loc Location, content string, version FingerprintVersion) string {
	h := sha256.New()
	switch version {
	case FingerprintV2:
		// Drop start_line; normalise file_path. Null-byte separators
		// preserve the "ab||c" vs "a||bc" disambiguation that V1 had.
		_, _ = fmt.Fprintf(h, "%s\x00%s\x00%s", ruleID, normaliseFilePath(loc.FilePath), content)
	default:
		// V1 (or unknown → V1): keep the historical algorithm bit-for-bit.
		_, _ = fmt.Fprintf(h, "%s\x00%s\x00%d\x00%s", ruleID, loc.FilePath, loc.StartLine, content)
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

// normaliseFilePath rewrites loc.FilePath to a stable form that
// survives the most common cross-environment differences:
//
//   - backslashes → forward slashes (Windows runners),
//   - drop leading `./`,
//   - collapse `..` and duplicate separators via filepath.Clean (then
//     re-normalise separators after Clean on platforms that use `\`).
//
// We do NOT attempt to resolve to a git-root-relative path here: that
// would require shelling out from the hashing hot path and the upstream
// scanner is the right place to make paths repo-relative before they
// reach the fingerprint. This function just sands off the rough edges.
func normaliseFilePath(p string) string {
	if p == "" {
		return ""
	}
	// Flip backslashes BEFORE filepath.Clean. On Linux runners,
	// filepath.Clean treats `\` as a regular filename character, so
	// "http\middleware.go" survives intact unless we substitute first.
	// This matters because a Windows runner produces backslashes that
	// must hash identically to the Linux equivalent.
	p = strings.ReplaceAll(p, "\\", "/")
	// Drop leading ./ that nox emits when scan root and finding share a
	// prefix. This is the single largest source of fingerprint drift
	// observed in the wild (nox scan ./http vs nox scan . differs by
	// exactly this prefix).
	for strings.HasPrefix(p, "./") {
		p = strings.TrimPrefix(p, "./")
	}
	// Path-elements `.` and `..` collapse via Clean. Force forward
	// slashes regardless of OS so Windows and Linux runners agree.
	p = filepath.ToSlash(filepath.Clean(p))
	// filepath.Clean(".") returns ".". Normalise that down to the empty
	// string so a degenerate path (only "./" or ".") doesn't accidentally
	// hash a literal "." into the digest.
	if p == "." {
		return ""
	}
	return p
}
