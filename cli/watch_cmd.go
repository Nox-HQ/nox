package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	nox "github.com/nox-hq/nox/core"
	"github.com/nox-hq/nox/core/badge"
)

func runWatch(args []string) int {
	fs := flag.NewFlagSet("watch", flag.ContinueOnError)
	var (
		debounce time.Duration
		jsonFlag bool
	)
	fs.DurationVar(&debounce, "debounce", 500*time.Millisecond, "debounce interval for file changes")
	fs.BoolVar(&jsonFlag, "json", false, "output as JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	target := "."
	if fs.NArg() > 0 {
		target = fs.Arg(0)
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: creating watcher: %v\n", err)
		return 2
	}
	defer watcher.Close()

	// Recursively add directories.
	if err := addDirsRecursive(watcher, target); err != nil {
		fmt.Fprintf(os.Stderr, "error: watching directories: %v\n", err)
		return 2
	}

	// Signal handling.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Initial scan.
	fmt.Printf("watch: scanning %s (debounce: %s)\n", target, debounce)
	printScanResults(target, jsonFlag)

	// Debounced event loop.
	var mu sync.Mutex
	var timer *time.Timer

	resetTimer := func() {
		mu.Lock()
		defer mu.Unlock()
		if timer != nil {
			timer.Stop()
		}
		timer = time.AfterFunc(debounce, func() {
			fmt.Print("\033[2J\033[H") // clear terminal
			fmt.Printf("watch: re-scanning %s\n", target)
			printScanResults(target, jsonFlag)
		})
	}

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return 0
			}
			if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) || event.Has(fsnotify.Remove) {
				// Add new directories if created.
				if event.Has(fsnotify.Create) {
					info, err := os.Stat(event.Name)
					if err == nil && info.IsDir() {
						_ = addDirsRecursive(watcher, event.Name)
					}
				}
				resetTimer()
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return 0
			}
			fmt.Fprintf(os.Stderr, "watch error: %v\n", err)
		case <-sigCh:
			fmt.Println("\nwatch: stopped")
			return 0
		}
	}
}

func printScanResults(target string, jsonOutput bool) {
	result, err := nox.RunScan(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: scan failed: %v\n", err)
		return
	}

	ff := result.Findings.ActiveFindings()
	suppressed := len(result.Findings.Findings()) - len(ff)
	counts := badge.CountBySeverity(ff)

	fmt.Printf("[results] %d finding(s)", len(ff))
	if suppressed > 0 {
		fmt.Printf(" (%d suppressed)", suppressed)
	}
	if len(counts) > 0 {
		parts := make([]string, 0, len(counts))
		for sev, count := range counts {
			parts = append(parts, fmt.Sprintf("%d %s", count, string(sev)))
		}
		fmt.Printf(" — %s", strings.Join(parts, ", "))
	}
	fmt.Println()

	if result.PolicyResult != nil {
		fmt.Printf("[policy] %s\n", result.PolicyResult.Summary)
	}
}

func addDirsRecursive(watcher *fsnotify.Watcher, root string) error {
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() {
			return nil
		}
		base := filepath.Base(path)
		if base == ".git" || base == "node_modules" || base == ".nox" {
			return filepath.SkipDir
		}
		return watcher.Add(path)
	})
}
