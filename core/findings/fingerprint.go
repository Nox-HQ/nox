package findings

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
)

// FingerprintVersion controls which fingerprint algorithm runs. Default
// is V1 (line + path + content + rule_id) for full backwards compatibility
// with existing baselines. V2 (path + content + rule_id, with path
// normalised to forward-slash + repo-root-relative) drops the line
// number so trivial diffs — import shifts, gofmt, comment edits — don't
// invalidate baselined findings.
//
// V2 is opt-in. Switch it on via:
//
//   - environment: NOX_FINGERPRINT_VERSION=2
//   - Go API:      findings.SetFingerprintVersion(2)
//   - CLI flag:    nox scan --fingerprint-version 2 (wired in cmd/)
//
// Once a consumer opts in, every newly-computed fingerprint uses V2 and
// the baseline file's per-entry fingerprint becomes incompatible with
// V1 — `nox baseline update` will re-compute. Plan to run both
// algorithms during a transition window if you can't update every
// downstream consumer at once.
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
	// configuration is set. Currently V1 for backwards compatibility;
	// scheduled to flip to V2 in the next major release.
	DefaultFingerprintVersion = FingerprintV1
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
	// filepath.Clean(".") returns "." — keep it explicit rather than
	// hashing the empty string.
	if p == "." {
		return ""
	}
	return p
}
