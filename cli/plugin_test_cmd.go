package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/nox-hq/nox/registry"
)

// runPluginTest runs a built plugin binary the way a scan will: registered
// with a host under its track's policy, then its scan tool invoked against a
// directory. It goes through runPluginBinaries, the same code a scan uses, so
// a pass here means a scan will run it and a failure names what a scan would
// have degraded.
//
// This replaces a placeholder that printed "not yet implemented" while the
// command was advertised in `nox plugin`'s usage. What it now checks is the
// failure that kept nox-plugin-freshness unreleased: it declared network hosts
// its track did not allow, so every scan rejected it at registration, and
// nothing short of installing it and scanning said so.
//
// In-process protocol conformance is a different check and stays where it is:
// sdk.RunForTrack, called from the TestConformance the scaffold generates.
func runPluginTest(args []string) int {
	fs := flag.NewFlagSet("plugin test", flag.ContinueOnError)
	track := fs.String("track", "", "track the plugin is published under (default: read from plugin.yaml beside the binary, then in the current directory)")
	target := fs.String("target", ".", "directory to run the plugin's scan tool against")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: nox plugin test [--track <track>] [--target <dir>] <plugin-binary>")
		fmt.Fprintln(os.Stderr, "\nRegisters the binary under its track's policy and runs its scan tool, exactly as a scan would.")
		fs.PrintDefaults()
	}
	if err := parseFlagsAnywhere(fs, args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return 2
	}
	bin, err := filepath.Abs(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "nox plugin test: %v\n", err)
		return 2
	}
	if st, err := os.Stat(bin); err != nil || st.IsDir() {
		fmt.Fprintf(os.Stderr, "nox plugin test: %s is not a plugin binary\n", fs.Arg(0))
		return 2
	}

	tr := *track
	if tr == "" {
		tr = trackFromManifest(filepath.Dir(bin))
	}
	if tr == "" {
		fmt.Fprintln(os.Stderr, "nox plugin test: no --track given and no plugin.yaml declares one; the policy a plugin runs under depends on it")
		return 2
	}
	if !registry.ValidTrack(registry.Track(tr)) {
		fmt.Fprintf(os.Stderr, "nox plugin test: unknown track %q\n", tr)
		return 2
	}

	out, err := runPluginBinaries(context.Background(), *target,
		[]installedPlugin{{name: filepath.Base(bin), path: bin, track: registry.Track(tr)}}, nil, nil, false)
	if err != nil {
		fmt.Printf("FAIL  %s under the %s policy: %v\n", filepath.Base(bin), tr, err)
		return 1
	}
	if out != nil && len(out.Degradations) > 0 {
		for _, d := range out.Degradations {
			fmt.Printf("FAIL  %s\n      %s\n", d.Detail, d.Impact)
		}
		return 1
	}
	n := 0
	if out != nil {
		n = len(out.Findings)
	}
	fmt.Printf("PASS  %s registered under the %s policy, and its scan ran against %s: %d finding(s)\n",
		filepath.Base(bin), tr, *target, n)
	return 0
}

// trackFromManifest reads `track:` from plugin.yaml beside the binary, then
// from the current directory, which is where `make build` leaves it.
func trackFromManifest(binDir string) string {
	for _, dir := range []string{binDir, "."} {
		b, err := os.ReadFile(filepath.Join(dir, "plugin.yaml"))
		if err != nil {
			continue
		}
		var m struct {
			Track string `yaml:"track"`
		}
		if yaml.Unmarshal(b, &m) == nil && strings.TrimSpace(m.Track) != "" {
			return strings.TrimSpace(m.Track)
		}
	}
	return ""
}
