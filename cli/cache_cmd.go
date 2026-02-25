package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/nox-hq/nox/core/cache"
)

func runCache(args []string) int {
	cacheFS := flag.NewFlagSet("cache", flag.ContinueOnError)
	if err := cacheFS.Parse(args); err != nil {
		return 2
	}

	if cacheFS.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "Usage: nox cache <command>")
		fmt.Fprintln(os.Stderr, "Commands:")
		fmt.Fprintln(os.Stderr, "  clear   Clear the scan cache")
		fmt.Fprintln(os.Stderr, "  status  Show cache statistics")
		return 2
	}

	sub := cacheFS.Arg(0)
	switch sub {
	case "clear":
		return runCacheClear()
	case "status":
		return runCacheStatus()
	default:
		fmt.Fprintf(os.Stderr, "unknown cache command: %s\n", sub)
		return 2
	}
}

func runCacheClear() int {
	c := cache.New()
	if err := c.Clear(); err != nil {
		fmt.Fprintf(os.Stderr, "error: clearing cache: %v\n", err)
		return 2
	}
	fmt.Println("scan cache cleared")
	return 0
}

func runCacheStatus() int {
	c := cache.New()
	if err := c.Load(); err != nil {
		fmt.Fprintf(os.Stderr, "error: loading cache: %v\n", err)
		return 2
	}

	entries, sizeBytes := c.Stats()
	fmt.Printf("cache entries: %d\n", entries)
	if sizeBytes > 0 {
		fmt.Printf("cache size: %s\n", formatBytes(sizeBytes))
	} else {
		fmt.Printf("cache size: 0 B\n")
	}
	return 0
}

func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
