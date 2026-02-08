package oci

import (
	"errors"
	"runtime"

	"github.com/nox-hq/nox/registry"
)

// ErrNoPlatformMatch indicates no artifact matches the current platform.
var ErrNoPlatformMatch = errors.New("no artifact matches current platform")

// SelectArtifact returns the first artifact matching the current OS and architecture.
func SelectArtifact(artifacts []registry.PlatformArtifact) (*registry.PlatformArtifact, error) {
	return SelectArtifactFor(artifacts, runtime.GOOS, runtime.GOARCH)
}

// SelectArtifactFor returns the first artifact matching the given OS and architecture.
func SelectArtifactFor(artifacts []registry.PlatformArtifact, goos, goarch string) (*registry.PlatformArtifact, error) {
	for i := range artifacts {
		if artifacts[i].OS == goos && artifacts[i].Arch == goarch {
			return &artifacts[i], nil
		}
	}
	return nil, ErrNoPlatformMatch
}
