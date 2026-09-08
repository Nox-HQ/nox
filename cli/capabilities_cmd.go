package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/nox-hq/nox/core/capability"
)

// runAnalysisCapabilities prints what this installation can establish, and —
// more usefully — what it cannot.
//
// The second half is the reason the command exists. An operator reading a clean
// scan has no way to tell whether nox looked for something and found nothing,
// or never had the ability to look. Documentation could say so, and the
// documentation would drift; this is generated from the registry the scan
// itself uses, so it cannot describe a capability the scan does not have.
//
// It is deliberately NOT called `nox capabilities`. core/analyzers/ai uses
// "capability" for what an AI agent's tools can do, rendered by
// `nox agent-graph`, and two commands a letter apart meaning different things
// is a documentation problem that no amount of documentation fixes.
func runAnalysisCapabilities(args []string) int {
	fs := flag.NewFlagSet("analysis-capabilities", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "emit the matrix as JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	registry := capability.DefaultRegistry()

	type row struct {
		Capability string   `json:"capability"`
		Provided   bool     `json:"provided"`
		Providers  []string `json:"providers,omitempty"`
	}
	rows := make([]row, 0, len(capability.All()))
	for _, c := range capability.All() {
		rows = append(rows, row{
			Capability: string(c),
			Provided:   registry.Provided(c),
			Providers:  registry.ProvidedBy(c),
		})
	}

	if *jsonOut {
		out, err := json.MarshalIndent(struct {
			Capabilities []row    `json:"capabilities"`
			Missing      []string `json:"missing"`
		}{rows, capsToStrings(registry.Missing())}, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 2
		}
		fmt.Println(string(out))
		return 0
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "ANALYSIS CAPABILITY\tPROVIDED BY")
	for _, r := range rows {
		provided := "— not provided"
		if r.Provided {
			provided = strings.Join(r.Providers, ", ")
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\n", r.Capability, provided)
	}
	if err := w.Flush(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}

	// The standing limits, printed whether or not anything is missing.
	//
	// They used to print only alongside a missing capability, which was fine
	// while two were missing and became a silent regression the moment
	// core/callgraph filled the last of them: a full matrix with no caveat
	// under it reads as a full answer. None of these limits is a gap an
	// operator can close by installing something — they are properties of what
	// a scanner is — so they belong here unconditionally.
	fmt.Println("\nWhat a full matrix still does not mean:")
	fmt.Println("  - a scan executes nothing, so dynamic_verification is never")
	fmt.Println("    answered by `nox scan` however it is listed above")
	fmt.Println("  - call_graph and entry_point are answered for Go only; for every")
	fmt.Println("    other language a finding's own matrix reads `unsupported`")
	fmt.Println("  - the call graph answers EXISTENTIALLY. It can show a path and")
	fmt.Println("    name the calls; it never reports that no path exists, because")
	fmt.Println("    interface dispatch, function values and reflection are calls")
	fmt.Println("    it cannot see")
	fmt.Println("\nRun `nox why <finding>` for what was actually established about one finding.")

	missing := registry.Missing()
	if len(missing) == 0 {
		return 0
	}

	// The wording here matters more than the list. An operator who reads
	// "not provided" as "not a problem" has drawn exactly the inference this
	// whole model exists to prevent.
	fmt.Printf("\n%d capabilit%s no implementation on this installation:\n",
		len(missing), map[bool]string{true: "y has", false: "ies have"}[len(missing) == 1])
	for _, c := range missing {
		fmt.Printf("  %s\n", c)
	}
	fmt.Println("\nA scan cannot answer these questions, and its silence about them is not\n" +
		"an all-clear. Install a plugin that provides them, or read findings that\n" +
		"depend on them as unevaluated rather than as cleared.")
	return 0
}

func capsToStrings(cs []capability.AnalysisCapability) []string {
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, string(c))
	}
	return out
}
