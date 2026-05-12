package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

// runDoctor reports on the local environment so an operator can
// self-diagnose missing prerequisites, broken plugin state, and
// configuration drift before opening an issue.
func runDoctor(_ []string) int {
	fmt.Printf("nox doctor\n")
	fmt.Printf("  version:        %s\n", version)
	fmt.Printf("  commit:         %s\n", commit)
	fmt.Printf("  built:          %s\n", date)
	fmt.Printf("  go runtime:     %s on %s/%s\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)

	fmt.Println()
	fmt.Println("[paths]")
	if exe, err := os.Executable(); err == nil {
		fmt.Printf("  executable:     %s\n", exe)
	}
	if home, err := os.UserHomeDir(); err == nil {
		fmt.Printf("  HOME:           %s\n", home)
	}
	fmt.Printf("  state:          %s\n", DefaultStatePath())
	fmt.Printf("  cwd:            %s\n", mustGetwd())

	fmt.Println()
	fmt.Println("[plugins]")
	st, err := LoadState(DefaultStatePath())
	switch {
	case err != nil:
		fmt.Printf("  ! error reading state: %v\n", err)
	case len(st.Plugins) == 0:
		fmt.Printf("  no plugins installed\n")
	default:
		for i := range st.Plugins {
			p := &st.Plugins[i]
			tag := p.TrustLevel
			if tag == "" {
				tag = "unsigned"
			}
			fmt.Printf("  %s@%s  [%s]  %s\n", p.Name, p.Version, tag, p.BinaryPath)
			if _, err := os.Stat(p.BinaryPath); err != nil {
				fmt.Printf("    ! binary missing: %v\n", err)
			}
		}
	}

	fmt.Println()
	fmt.Println("[external tools]")
	for _, bin := range []string{"git", "go", "docker"} {
		if path, err := exec.LookPath(bin); err == nil {
			fmt.Printf("  %s: %s\n", bin, path)
		} else {
			fmt.Printf("  %s: not on PATH (%s)\n", bin, err)
		}
	}

	fmt.Println()
	fmt.Println("[config]")
	if _, err := os.Stat(filepath.Join(mustGetwd(), ".nox.yaml")); err == nil {
		fmt.Printf("  .nox.yaml present\n")
	} else {
		fmt.Printf("  .nox.yaml not found\n")
	}
	if _, err := os.Stat(filepath.Join(mustGetwd(), ".gitignore")); err == nil {
		fmt.Printf("  .gitignore present\n")
	} else {
		fmt.Printf("  .gitignore not found — entropy rules will scan everything\n")
	}

	// reportCIVersionDrift prints its own `[ci]` section header so we
	// don't end up with a blank one when there's nothing to report.
	reportCIVersionDrift(repoRoot(), version)

	return 0
}

// semverRE matches a literal X.Y.Z so we can distinguish a real
// release tag from a dev build like "dev" or "v0.10.0-3-gabc". The
// drift comparison only runs when the local binary has a real semver
// to compare against.
var semverRE = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

// ciNoxVersionRE matches `go install github.com/nox-hq/nox/cli@vX.Y.Z`
// or `nox-hq/nox@vX.Y.Z` references commonly used in CI workflows.
// Captures the bare version (no `v` prefix) so it compares directly
// against stripVPrefix(localVersion).
var ciNoxVersionRE = regexp.MustCompile(`nox-hq/nox(?:/cli)?@v?(\d+\.\d+\.\d+)`)

// repoRoot resolves the enclosing git repository root via
// `git rev-parse --show-toplevel` so `nox doctor` invoked from a
// subdirectory still picks up the top-level `.github/workflows`.
// Falls back to the current working directory when not in a git repo.
func repoRoot() string {
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err == nil {
		root := strings.TrimSpace(string(out))
		if root != "" {
			return root
		}
	}
	return mustGetwd()
}

// reportCIVersionDrift walks .github/workflows/*.yml at repoRoot and
// warns when a pinned nox version differs from the local binary. The
// function owns its `[ci]` section header — print nothing (no blank
// header) when there's nothing to report:
//
//   - no .github/workflows directory  → silent (probably non-CI'd repo).
//   - directory exists but no nox refs → silent (nox not used in CI).
//   - localVersion is not a real semver (e.g. "dev") → print the
//     pinned versions but skip the DRIFT comparison.
//
// Tolerant of read errors throughout — doctor is informational and
// must never become fatal.
func reportCIVersionDrift(rRoot, localVersion string) {
	workflowsDir := filepath.Join(rRoot, ".github", "workflows")
	entries, err := os.ReadDir(workflowsDir)
	if err != nil {
		return // silent: probably a non-CI'd repo
	}
	type drift struct {
		file    string
		version string
	}
	var pinned []drift
	for _, e := range entries {
		if e.IsDir() || (!hasSuffix(e.Name(), ".yml") && !hasSuffix(e.Name(), ".yaml")) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(workflowsDir, e.Name()))
		if err != nil {
			continue
		}
		for _, m := range ciNoxVersionRE.FindAllStringSubmatch(string(data), -1) {
			pinned = append(pinned, drift{file: e.Name(), version: m[1]})
		}
	}
	if len(pinned) == 0 {
		return // silent: workflows exist but don't reference nox
	}

	// We have something to print — emit the section header now.
	fmt.Println()
	fmt.Println("[ci]")

	localBare := stripVPrefix(localVersion)
	canCompare := semverRE.MatchString(localBare)
	if !canCompare {
		fmt.Printf("  local nox version %q is not a release tag; skipping drift comparison\n", localVersion)
	}
	allMatch := true
	for _, p := range pinned {
		switch {
		case !canCompare:
			fmt.Printf("  %s pins nox@v%s\n", p.file, p.version)
		case p.version == localBare:
			fmt.Printf("  ok    %s pins nox@v%s (local: %s)\n", p.file, p.version, localVersion)
		default:
			allMatch = false
			fmt.Printf("  DRIFT %s pins nox@v%s (local: %s)\n", p.file, p.version, localVersion)
		}
	}
	if canCompare && !allMatch {
		fmt.Printf("  ! CI and local versions differ — fingerprints / findings may diverge\n")
		fmt.Printf("    bump CI to v%s, or `go install github.com/nox-hq/nox/cli@v%s` locally\n", localBare, pinned[0].version)
	}
}

func hasSuffix(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}

func stripVPrefix(v string) string {
	if v != "" && v[0] == 'v' {
		return v[1:]
	}
	return v
}

func mustGetwd() string {
	if d, err := os.Getwd(); err == nil {
		return d
	}
	return "(unknown)"
}
