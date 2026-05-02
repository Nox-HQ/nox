package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/vex"
)

// runVex dispatches `nox vex <subcmd>`. Currently supports `init` to bootstrap
// an OpenVEX document from findings.json. `sync` is a planned subcommand for
// keeping vex.json aligned with subsequent scans.
func runVex(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: nox vex <init> [flags]")
		return 2
	}
	switch args[0] {
	case "init":
		return runVexInit(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown vex subcommand: %s\n", args[0])
		fmt.Fprintln(os.Stderr, "Usage: nox vex <init> [flags]")
		return 2
	}
}

func runVexInit(args []string) int {
	fs := flag.NewFlagSet("vex init", flag.ContinueOnError)
	var (
		inputPath  string
		outputPath string
		product    string
		force      bool
	)
	fs.StringVar(&inputPath, "input", "findings.json", "path to findings.json from a previous scan")
	fs.StringVar(&outputPath, "output", "vex.json", "destination path for the generated stub")
	fs.StringVar(&product, "product", "", "product identifier to embed in each statement (typically the Go module path)")
	fs.BoolVar(&force, "force", false, "overwrite output if it already exists")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	if !force {
		if _, err := os.Stat(outputPath); err == nil {
			fmt.Fprintf(os.Stderr, "error: %s already exists; pass --force to overwrite\n", outputPath)
			return 2
		}
	}

	raw, err := os.ReadFile(inputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: reading %s: %v\n", inputPath, err)
		return 2
	}

	var items []findings.Finding
	if err := json.Unmarshal(raw, &items); err != nil {
		fmt.Fprintf(os.Stderr, "error: parsing %s: %v\n", inputPath, err)
		return 2
	}

	doc := vex.BuildStub(items, product)

	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: marshalling vex doc: %v\n", err)
		return 2
	}

	if err := os.WriteFile(outputPath, out, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "error: writing %s: %v\n", outputPath, err)
		return 2
	}

	fmt.Printf("nox vex init: wrote %d statements to %s\n", len(doc.Statements), outputPath)
	fmt.Println("Edit each statement's status / justification / impact_statement before committing.")
	return 0
}
