package cli

import (
	"regexp"
	"runtime/debug"
	"strings"
)

// buildStamp is what a build says about itself: the three values the release
// pipeline sets with -ldflags.
type buildStamp struct {
	version, commit, date string
}

// releaseTagRE matches a module version that is a release tag: vX.Y.Z with an
// optional pre-release. pseudoVersionRE matches the suffix the go command gives
// a version it invented for an untagged commit, which is not a release.
var (
	releaseTagRE    = regexp.MustCompile(`^v\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$`)
	pseudoVersionRE = regexp.MustCompile(`(^|[.-])\d{14}-[0-9a-f]{12}$`)
)

// stampFromBuildInfo fills the placeholders of a build that was not stamped
// with -ldflags from what the go command recorded in the binary. Main calls it
// with the stamp cmd/nox received.
//
// `go install github.com/nox-hq/nox/cmd/nox@v1.66.0` records the module version
// and nothing else, so such a build reports its release and leaves commit and date
// unknown. A build from a checkout records the commit but is not a release:
// its version is one the go command made up, so it stays "dev", and a commit
// built with uncommitted changes says so. The date is left alone: the go
// command records when the commit was made, not when the binary was built. A
// value that was stamped is never replaced.
func stampFromBuildInfo(s buildStamp, info *debug.BuildInfo) buildStamp {
	if info == nil {
		return s
	}
	if v := info.Main.Version; s.version == "dev" && releaseTagRE.MatchString(v) && !pseudoVersionRE.MatchString(v) {
		s.version = strings.TrimPrefix(v, "v")
	}
	if s.commit != "none" {
		return s
	}
	revision, modified := "", false
	for _, kv := range info.Settings {
		switch kv.Key {
		case "vcs.revision":
			revision = kv.Value
		case "vcs.modified":
			modified = kv.Value == "true"
		}
	}
	if revision == "" {
		return s
	}
	s.commit = revision
	if modified {
		s.commit += "+dirty"
	}
	return s
}
