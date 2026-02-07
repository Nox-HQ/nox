package findings

import (
	"crypto/sha256"
	"fmt"
)

// ComputeFingerprint produces a deterministic SHA-256 hex digest from the
// combination of ruleID, location file path, location start line, and the
// matched content. The fingerprint is stable across runs as long as the
// inputs are identical, making it suitable for deduplication and change
// tracking between scans.
func ComputeFingerprint(ruleID string, loc Location, content string) string {
	h := sha256.New()
	// Write each component separated by a null byte to avoid ambiguous
	// concatenations (e.g. ruleID="ab", path="c" vs ruleID="a", path="bc").
	_, _ = fmt.Fprintf(h, "%s\x00%s\x00%d\x00%s", ruleID, loc.FilePath, loc.StartLine, content)
	return fmt.Sprintf("%x", h.Sum(nil))
}
