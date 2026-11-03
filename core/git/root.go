package git

import (
	"errors"
	"sort"
	"strings"
)

// ErrShallowClone is returned by RootCommit for a shallow clone, whose
// apparent root is only the depth boundary and moves with every fetch.
var ErrShallowClone = errors.New("shallow clone: the root commit is not in this checkout")

// RootCommit returns the repository's identity: its root commit, the one commit
// every later state of the repository shares. Where history joins several roots
// (merged unrelated histories) it is the smallest hash, so the answer does not
// depend on the order git lists them.
//
// A shallow clone is refused rather than answered. Its "root" is the depth
// boundary, a different commit on every CI run of a depth-1 checkout, so it
// would name a new repository each time.
func RootCommit(dir string) (string, error) {
	shallow, err := runGit(dir, "rev-parse", "--is-shallow-repository")
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(shallow) == "true" {
		return "", ErrShallowClone
	}
	out, err := runGit(dir, "rev-list", "--max-parents=0", "HEAD")
	if err != nil {
		return "", err
	}
	roots := splitLines(strings.TrimSpace(out))
	if len(roots) == 0 || roots[0] == "" {
		return "", errors.New("no root commit: the repository has no commits")
	}
	sort.Strings(roots)
	return roots[0], nil
}
