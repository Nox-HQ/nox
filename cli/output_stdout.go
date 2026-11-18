package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"slices"

	nox "github.com/nox-hq/nox/core"
	"github.com/nox-hq/nox/core/report/sbom"
)

// stdoutOutput is the --output value that streams the report on stdout instead
// of writing it into a directory.
const stdoutOutput = "-"

// stdoutFormats are the formats --output - can stream: each is one document.
// html is left out; it is a page to open, not a report to pipe.
var stdoutFormats = []string{"json", "sarif", "cdx", "spdx"}

// errStdoutOneFormat is the usage error for --output - with anything but one
// format. The wording is part of the contract: consumers match on it.
var errStdoutOneFormat = errors.New("`--output -` streams one report; choose a single --format")

// validateStdoutFormats checks a --output - run asks for exactly one format
// that can be streamed.
func validateStdoutFormats(formats []string) error {
	if len(formats) != 1 {
		return errStdoutOneFormat
	}
	if !slices.Contains(stdoutFormats, formats[0]) {
		return fmt.Errorf("--format %s cannot be streamed with `--output -`: use one of %v", formats[0], stdoutFormats)
	}
	return nil
}

// streamReport writes the one report of a --output - run to w. Nothing is
// written unless the whole document was generated, so a failure leaves stdout
// empty rather than holding half a document. It returns the exit code, 0 on
// success.
func streamReport(w io.Writer, format string, result *nox.ScanResult, version string, offline, prioritize bool) int {
	var err error
	switch format {
	case "json":
		r := result.JSONReporter(version)
		r.Offline = offline
		r.Prioritize = prioritize
		err = r.Write(w, result.Findings)
	case "sarif":
		err = result.SARIFReporter(version).Write(w, result.Findings)
	case "cdx", "spdx":
		if !result.Scope.Has(nox.ScopeDeps) {
			fmt.Fprintf(os.Stderr, "error: --format %s needs the deps scope, which this scan did not run\n", format)
			return 2
		}
		if format == "cdx" {
			err = result.CycloneDX(version).Write(w, result.Inventory)
		} else {
			err = sbom.NewSPDXReporter(version).Write(w, result.Inventory)
		}
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: writing %s report to stdout: %v\n", format, err)
		return 2
	}
	return 0
}
