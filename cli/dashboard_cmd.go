package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	nox "github.com/nox-hq/nox/core"
	"github.com/nox-hq/nox/server"
)

func runDashboard(args []string) int {
	fs := flag.NewFlagSet("dashboard", flag.ContinueOnError)
	var (
		output    string
		noBrowser bool
	)
	fs.StringVar(&output, "output", "", "output HTML file path (default: temp file)")
	fs.BoolVar(&noBrowser, "no-browser", false, "write HTML file without opening browser")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	target := "."
	if fs.NArg() > 0 {
		target = fs.Arg(0)
	}

	fmt.Printf("nox — scanning %s\n", target)
	result, err := nox.RunScan(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: scan failed: %v\n", err)
		return 2
	}

	active := result.Findings.ActiveFindings()
	suppressed := len(result.Findings.Findings()) - len(active)
	if suppressed > 0 {
		fmt.Printf("[results] %d findings (%d suppressed)\n", len(active), suppressed)
	} else {
		fmt.Printf("[results] %d findings\n", len(active))
	}

	html, err := server.GenerateDashboardHTML(result, version, target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: generating dashboard: %v\n", err)
		return 2
	}

	// Determine output path.
	outPath := output
	if outPath == "" {
		tmpDir := os.TempDir()
		outPath = filepath.Join(tmpDir, "nox-dashboard.html")
	}

	// Ensure parent directory exists.
	if dir := filepath.Dir(outPath); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "error: creating directory: %v\n", err)
			return 2
		}
	}

	if err := os.WriteFile(outPath, []byte(html), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "error: writing dashboard: %v\n", err)
		return 2
	}

	fmt.Printf("[dashboard] wrote %s\n", outPath)

	if !noBrowser {
		if err := openBrowser(outPath); err != nil {
			fmt.Printf("[dashboard] could not open browser: %v\n", err)
			fmt.Printf("[dashboard] open %s in your browser\n", outPath)
		}
	}

	return 0
}

func openBrowser(path string) error {
	url := "file://" + path
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", url).Start()
	case "linux":
		return exec.Command("xdg-open", url).Start()
	case "windows":
		return exec.Command("cmd", "/c", "start", url).Start()
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}
