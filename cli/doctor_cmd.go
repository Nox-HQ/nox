package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
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

	fmt.Println()
	fmt.Println("[ci]")
	reportCIVersionDrift(mustGetwd(), version)

	return 0
}

// ciNoxVersionRE matches the `go install github.com/nox-hq/nox/cli@vX.Y.Z`
// or `nox-hq/nox@vX.Y.Z` references commonly used in CI workflows. The
// version is captured so doctor can compare it against the local
// binary's version and flag drift.
var ciNoxVersionRE = regexp.MustCompile(`nox-hq/nox(?:/cli)?@v?(\d+\.\d+\.\d+)`)

// reportCIVersionDrift walks .github/workflows/*.yml and warns when a
// pinned nox version differs from the local binary. Silent when no
// workflow files reference nox. Tolerant of read errors — doctor is
// informational, never fatal.
func reportCIVersionDrift(repoRoot, localVersion string) {
	workflowsDir := filepath.Join(repoRoot, ".github", "workflows")
	entries, err := os.ReadDir(workflowsDir)
	if err != nil {
		// No .github/workflows — not necessarily a problem (could be a
		// non-CI'd repo). Stay silent.
		return
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
		fmt.Printf("  no nox version pin found in .github/workflows/\n")
		return
	}
	// `localVersion` may be a dev build (e.g. "dev") — only compare
	// when we have a real semver locally.
	localBare := stripVPrefix(localVersion)
	allMatch := true
	for _, p := range pinned {
		if p.version != localBare {
			allMatch = false
		}
		marker := "ok"
		if p.version != localBare {
			marker = "DRIFT"
		}
		fmt.Printf("  %s %s pins nox@v%s (local: %s)\n", marker, p.file, p.version, localVersion)
	}
	if !allMatch {
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
