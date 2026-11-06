package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"

	nox "github.com/nox-hq/nox/core"
)

// runSBOM writes the SBOM of one built artifact. It is what nox's own release
// attaches to each archive.
func runSBOM(args []string) int {
	return sbomCmd(args, os.Stdout, os.Stderr)
}

func sbomCmd(args []string, out, errw io.Writer) int {
	fs := flag.NewFlagSet("sbom", flag.ContinueOnError)
	fs.SetOutput(errw)
	output := fs.String("output", "", "write the SBOM to this file (default: stdout)")
	format := fs.String("format", nox.SBOMFormatSPDX, "spdx (SPDX 2.3) or cyclonedx (CycloneDX 1.5)")
	fs.Usage = func() {
		_, _ = fmt.Fprintln(errw, "Usage: nox sbom <artifact> [-format spdx|cyclonedx] [-output file]")
		_, _ = fmt.Fprintln(errw, "  SBOM of a release archive (.tar.gz, .tgz, .tar, .zip) or a single file, with the artifact as its subject.")
		_, _ = fmt.Fprintln(errw, "  Offline and deterministic; Go executables are read from their embedded build info.")
		fs.PrintDefaults()
	}
	// Flags may follow the artifact, as goreleaser passes them.
	var positional []string
	for len(args) > 0 {
		if err := fs.Parse(args); err != nil {
			return 2
		}
		if args = fs.Args(); len(args) > 0 {
			positional, args = append(positional, args[0]), args[1:]
		}
	}
	if len(positional) != 1 || (*format != nox.SBOMFormatSPDX && *format != nox.SBOMFormatCycloneDX) {
		fs.Usage()
		return 2
	}
	data, err := nox.ArtifactSBOMAs(context.Background(), positional[0], version, *format)
	if err != nil {
		_, _ = fmt.Fprintf(errw, "nox sbom: %v\n", err)
		return 1
	}
	if *output == "" {
		_, _ = out.Write(append(data, '\n'))
		return 0
	}
	if err := os.WriteFile(*output, append(data, '\n'), 0o644); err != nil {
		_, _ = fmt.Fprintf(errw, "nox sbom: %v\n", err)
		return 1
	}
	return 0
}
