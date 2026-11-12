package cli

import (
	"runtime/debug"
	"testing"
)

// `go install github.com/nox-hq/nox/cli@v1.65.0` passes no -ldflags, so the
// three variables kept their placeholders and a released build introduced
// itself as "nox dev (commit: none, built: unknown)". The go command records
// the module version in the binary; a release build that was not stamped reads
// it from there.
func TestStampFromBuildInfo(t *testing.T) {
	settings := []debug.BuildSetting{
		{Key: "vcs.revision", Value: "caef67e0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6"},
		{Key: "vcs.time", Value: "2026-11-10T20:11:12Z"},
	}
	tests := []struct {
		name        string
		stamped     buildStamp
		main        string
		settings    []debug.BuildSetting
		wantVersion string
		wantCommit  string
		wantDate    string
	}{
		{
			name:        "go install of a release tag",
			stamped:     buildStamp{"dev", "none", "unknown"},
			main:        "v1.65.0",
			wantVersion: "1.65.0", wantCommit: "none", wantDate: "unknown",
		},
		{
			name:        "a stamped release build is left alone",
			stamped:     buildStamp{"1.65.0", "abc", "2026-11-10"},
			main:        "v9.9.9",
			settings:    settings,
			wantVersion: "1.65.0", wantCommit: "abc", wantDate: "2026-11-10",
		},
		{
			name:        "a build from a checkout is still dev, and says which commit",
			stamped:     buildStamp{"dev", "none", "unknown"},
			main:        "v1.65.1-0.20261110201112-caef67e0b1c2+dirty",
			settings:    settings,
			wantVersion: "dev", wantCommit: "caef67e0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6", wantDate: "unknown",
		},
		{
			name:        "a checkout with uncommitted changes is not that commit",
			stamped:     buildStamp{"dev", "none", "unknown"},
			main:        "v1.65.1-0.20261110201112-caef67e0b1c2+dirty",
			settings:    append([]debug.BuildSetting{{Key: "vcs.modified", Value: "true"}}, settings...),
			wantVersion: "dev", wantCommit: "caef67e0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6+dirty", wantDate: "unknown",
		},
		{
			name:        "go run and go test record no version",
			stamped:     buildStamp{"dev", "none", "unknown"},
			main:        "(devel)",
			wantVersion: "dev", wantCommit: "none", wantDate: "unknown",
		},
		{
			name:        "a pre-release tag is a version too",
			stamped:     buildStamp{"dev", "none", "unknown"},
			main:        "v2.0.0-rc.1",
			wantVersion: "2.0.0-rc.1", wantCommit: "none", wantDate: "unknown",
		},
		{
			name:        "no build info at all",
			stamped:     buildStamp{"dev", "none", "unknown"},
			wantVersion: "dev", wantCommit: "none", wantDate: "unknown",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var info *debug.BuildInfo
			if tc.main != "" || tc.settings != nil {
				info = &debug.BuildInfo{Main: debug.Module{Version: tc.main}, Settings: tc.settings}
			}
			got := stampFromBuildInfo(tc.stamped, info)
			want := buildStamp{tc.wantVersion, tc.wantCommit, tc.wantDate}
			if got != want {
				t.Errorf("stampFromBuildInfo = %+v, want %+v", got, want)
			}
		})
	}
}
