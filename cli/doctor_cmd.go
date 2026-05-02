package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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

	return 0
}

func mustGetwd() string {
	if d, err := os.Getwd(); err == nil {
		return d
	}
	return "(unknown)"
}
