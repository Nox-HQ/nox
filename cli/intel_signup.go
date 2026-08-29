package main

import (
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"
)

// runIntelSignup opens the web sign-up where a tenant is created.
//
// Deliberately a signpost rather than an implementation. Creating a tenant is
// where terms are accepted, billing is attached, an address is proven and abuse
// is throttled — none of which belong at a terminal, and all of which are why
// no comparable tool lets a CLI create an organisation. GitHub, Vercel and
// Cloudflare all create the org on the web and let the CLI only authenticate.
//
// The command exists anyway, because the alternative is a person typing
// `nox register`, getting "unknown subcommand", and guessing. A signpost that
// takes them to the right page is worth more than a missing command that is
// technically honest.
func runIntelSignup(args []string) int {
	fs := flag.NewFlagSet("intel register", flag.ContinueOnError)
	endpoint := fs.String("endpoint", os.Getenv("NOX_INTEL_ENDPOINT"),
		"intelligence service base URL (or NOX_INTEL_ENDPOINT)")
	noBrowser := fs.Bool("no-browser", false, "print the URL instead of opening a browser")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *endpoint == "" {
		fmt.Fprintf(os.Stderr, "Usage: nox intel register --endpoint URL\n\n")
		fmt.Fprintf(os.Stderr, "Opens the page where an organisation is created. Organisations are\n")
		fmt.Fprintf(os.Stderr, "not created from the command line: that is where terms, billing and\n")
		fmt.Fprintf(os.Stderr, "address verification live.\n\n")
		fmt.Fprintf(os.Stderr, "Already have an account?      nox intel login\n")
		fmt.Fprintf(os.Stderr, "Been invited by a colleague?  follow the link they sent you\n")
		return 2
	}
	base := strings.TrimRight(*endpoint, "/")
	if _, err := url.Parse(base); err != nil {
		fmt.Fprintf(os.Stderr, "nox intel register: bad endpoint: %v\n", err)
		return 2
	}
	target := base + "/signup"

	fmt.Printf("\nOrganisations are created on the web, not from the command line —\n")
	fmt.Printf("that is where terms, billing and address verification live.\n\n")
	fmt.Printf("Open:\n\n  %s\n\n", target)

	// CI has nobody to fill in a sign-up form. Opening a browser there is at
	// best noise and at worst a hung pipeline.
	if *noBrowser || isCI() {
		fmt.Printf("Once the organisation exists, sign in with:\n\n  nox intel login --endpoint %s\n", base)
		return 0
	}
	if err := openInBrowser(target); err != nil {
		fmt.Fprintf(os.Stderr, "Could not open a browser (%v). Use the URL above.\n", err)
	}
	fmt.Printf("Once the organisation exists, sign in with:\n\n  nox intel login --endpoint %s\n", base)
	return 0
}
