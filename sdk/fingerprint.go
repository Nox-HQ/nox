package sdk

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"
)

// Fingerprint derives a stable identifier for a finding.
//
// It exists because getting this wrong is invisible until it costs a whole
// team a day. A baseline matches on fingerprint, so a fingerprint that moves
// with the checkout directory makes every finding from the plugin reappear as
// net-new on any machine whose path differs — every CI runner, every
// git-worktree pre-push gate, any two developers. Locally the baseline matches
// and the scan is green, so the failure shows up only where nobody is looking,
// reads as a stale baseline, and invites a blanket baseline update that accepts
// the findings unreviewed into a baseline that will not match next time either
// (nox issue #454).
//
// filePath is made relative to workspaceRoot before hashing, so the value
// depends on the repository rather than on the machine that scanned it. parts
// are any further components that distinguish this finding from another of the
// same rule in the same file — the matched symbol, say. Line numbers are
// deliberately NOT included by the helper: a finding that shifts down when an
// import is added is still the same finding, and including the line makes the
// baseline entry expire on the next unrelated edit. Pass one explicitly if a
// plugin genuinely needs line-level identity.
//
// Components are length-prefixed rather than delimited, because a delimiter is
// only unambiguous if it cannot occur inside a component, and nothing here can
// promise that.
func Fingerprint(workspaceRoot, filePath, ruleID string, parts ...string) string {
	h := sha256.New()
	write := func(s string) {
		_, _ = fmt.Fprintf(h, "%d:%s\x00", len(s), s)
	}
	write(ruleID)
	write(RelativePath(workspaceRoot, filePath))
	for _, p := range parts {
		write(p)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// RelativePath returns filePath relative to workspaceRoot, so a finding names a
// file in the repository rather than a location on the scanning machine.
//
// A path that is already relative is returned unchanged, and so is one that
// cannot be related to the root — a different volume, or somewhere outside the
// workspace. Guessing in that case would be worse than leaving it alone: it
// would attribute the finding to the wrong file.
//
// Use this for the path you report as well as the one you hash. An absolute
// path in a finding cannot be matched against a repo-relative baseline entry,
// exclude pattern or VEX statement, and it leaks the scanning machine's
// directory layout into any report that gets uploaded.
func RelativePath(workspaceRoot, filePath string) string {
	if filePath == "" || workspaceRoot == "" || !filepath.IsAbs(filePath) {
		return filePath
	}
	absRoot, err := filepath.Abs(workspaceRoot)
	if err != nil {
		return filePath
	}
	rel, err := filepath.Rel(absRoot, filePath)
	if err != nil || strings.HasPrefix(rel, "..") {
		return filePath
	}
	return filepath.ToSlash(rel)
}
