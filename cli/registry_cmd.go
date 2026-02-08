package main

import (
	"flag"
	"fmt"
	"net/url"
	"os"
	"text/tabwriter"

	"github.com/nox-hq/nox/registry"
)

// runRegistry dispatches registry subcommands.
func runRegistry(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: nox registry <add|list|remove>")
		return 2
	}

	switch args[0] {
	case "add":
		return runRegistryAdd(args[1:])
	case "list":
		return runRegistryList(args[1:])
	case "remove":
		return runRegistryRemove(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown registry command: %s\n", args[0])
		fmt.Fprintln(os.Stderr, "Usage: nox registry <add|list|remove>")
		return 2
	}
}

// runRegistryAdd adds a registry source.
func runRegistryAdd(args []string) int {
	fs := flag.NewFlagSet("registry add", flag.ContinueOnError)
	var name string
	fs.StringVar(&name, "name", "", "registry name (default: derived from URL hostname)")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "Usage: nox registry add <url> [--name <name>]")
		return 2
	}

	rawURL := fs.Arg(0)

	if name == "" {
		u, err := url.Parse(rawURL)
		if err != nil || u.Host == "" {
			fmt.Fprintf(os.Stderr, "error: cannot derive name from URL %q; use --name\n", rawURL)
			return 2
		}
		name = u.Hostname()
	}

	statePath := DefaultStatePath()
	st, err := LoadState(statePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: loading state: %v\n", err)
		return 2
	}

	// Check for duplicate name.
	for _, s := range st.Sources {
		if s.Name == name {
			fmt.Fprintf(os.Stderr, "error: registry %q already exists\n", name)
			return 2
		}
	}

	st.Sources = append(st.Sources, registry.Source{Name: name, URL: rawURL})

	if err := SaveState(statePath, st); err != nil {
		fmt.Fprintf(os.Stderr, "error: saving state: %v\n", err)
		return 2
	}

	fmt.Printf("Registry %q added: %s\n", name, rawURL)
	return 0
}

// runRegistryList lists all configured registry sources.
func runRegistryList(args []string) int {
	statePath := DefaultStatePath()
	st, err := LoadState(statePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: loading state: %v\n", err)
		return 2
	}

	if len(st.Sources) == 0 {
		fmt.Println("No registries configured.")
		return 0
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tURL")
	for _, s := range st.Sources {
		fmt.Fprintf(w, "%s\t%s\n", s.Name, s.URL)
	}
	w.Flush()
	return 0
}

// runRegistryRemove removes a registry source by name.
func runRegistryRemove(args []string) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: nox registry remove <name>")
		return 2
	}

	name := args[0]
	statePath := DefaultStatePath()
	st, err := LoadState(statePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: loading state: %v\n", err)
		return 2
	}

	found := false
	for i, s := range st.Sources {
		if s.Name == name {
			st.Sources = append(st.Sources[:i], st.Sources[i+1:]...)
			found = true
			break
		}
	}

	if !found {
		fmt.Fprintf(os.Stderr, "error: registry %q not found\n", name)
		return 2
	}

	if err := SaveState(statePath, st); err != nil {
		fmt.Fprintf(os.Stderr, "error: saving state: %v\n", err)
		return 2
	}

	fmt.Printf("Registry %q removed.\n", name)
	return 0
}
