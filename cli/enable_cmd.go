package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/nox-hq/nox/core"
	"github.com/nox-hq/nox/core/plugincap"
)

const enableUsage = `Usage: nox enable [--dir DIR] [--dry-run] <check>... | all
       nox enable --list

Turn on optional checks for this project by what they check, not by which
plugin performs them. The choice is written to .nox.yaml so every developer and
CI run on the repository gets the same scan.

  --list      show the optional checks, what each covers and whether it is on
  --dir       project directory holding .nox.yaml (default ".")
  --dry-run   print the .nox.yaml that would be written and change nothing

"all" turns on every installed optional check. Checks that probe a running
system are never enabled this way; see nox attack plan.

Exit codes:
  0  enabled (or already on)
  2  could not enable: unknown check, not installed, or .nox.yaml not editable
`

// enableCandidate is an installed optional check a person can switch on.
type enableCandidate struct {
	slug, plugin, capability string
}

func runEnable(args []string) int {
	fs := flag.NewFlagSet("enable", flag.ContinueOnError)
	list := fs.Bool("list", false, "list optional checks")
	dir := fs.String("dir", ".", "project directory")
	dry := fs.Bool("dry-run", false, "print the result, change nothing")
	fs.Usage = func() { fmt.Fprint(os.Stderr, enableUsage) }
	if err := parseFlagsAnywhere(fs, args); err != nil {
		return 2
	}
	st, err := LoadState(DefaultStatePath())
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: loading state: %v\n", err)
		return 2
	}
	installed := installedOptionalChecks(st)
	if *list {
		return listOptionalChecks(installed, requiredPluginsForDir(*dir))
	}
	if fs.NArg() == 0 {
		fs.Usage()
		return 2
	}
	picked, err := resolveEnableArgs(fs.Args(), installed, st)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}
	return writeEnabled(*dir, picked, *dry)
}

func installedOptionalChecks(st *State) []enableCandidate {
	var out []enableCandidate
	for i := range st.Plugins {
		n := st.Plugins[i].Name
		if e := plugincap.Lookup(n); e.Class == plugincap.Optional {
			out = append(out, enableCandidate{plugincap.Slug(n), n, e.Capability})
		}
	}
	return out
}

func listOptionalChecks(installed []enableCandidate, required []string) int {
	if len(installed) == 0 {
		fmt.Println("No optional checks are installed.")
		return 0
	}
	for _, c := range installed {
		state := "off"
		if projectEnablesPlugin(required, c.plugin) {
			state = "on"
		}
		fmt.Printf("%-22s %-3s %s\n", c.slug, state, c.capability)
	}
	fmt.Println("\nTurn one on with: nox enable <check>   (or: nox enable all)")
	return 0
}

// resolveEnableArgs maps what the person typed to installed plugin names. A
// slug or a plugin name both work; "all" means every installed optional check.
func resolveEnableArgs(args []string, installed []enableCandidate, st *State) ([]enableCandidate, error) {
	var picked []enableCandidate
	seen := map[string]bool{}
	add := func(c enableCandidate) {
		if !seen[c.plugin] {
			seen[c.plugin] = true
			picked = append(picked, c)
		}
	}
	for _, a := range args {
		if a == "all" {
			for _, c := range installed {
				add(c)
			}
			continue
		}
		found := false
		for _, c := range installed {
			if a == c.slug || a == c.plugin {
				add(c)
				found = true
			}
		}
		if !found {
			return nil, notEnableable(a, st)
		}
	}
	if len(picked) == 0 {
		return nil, errors.New("no optional checks are installed; nothing to enable")
	}
	return picked, nil
}

func notEnableable(arg string, st *State) error {
	for i := range st.Plugins {
		n := st.Plugins[i].Name
		if (arg == n || arg == plugincap.Slug(n)) && plugincap.Lookup(n).Class == plugincap.Live {
			return fmt.Errorf("%s probes a running system and is never enabled for a scan; plan it with: nox attack plan", arg)
		}
	}
	for _, n := range plugincap.OptionalPlugins() {
		if arg == plugincap.Slug(n) || arg == n {
			return fmt.Errorf("%s is not installed; install it with: nox plugin install %s", arg, n)
		}
	}
	return fmt.Errorf("unknown check %q; see: nox enable --list", arg)
}

func writeEnabled(dir string, picked []enableCandidate, dry bool) int {
	path := filepath.Join(dir, ".nox.yaml")
	orig, readErr := os.ReadFile(path) //nolint:gosec // project config chosen by the user
	existed := readErr == nil
	if readErr != nil && !os.IsNotExist(readErr) {
		fmt.Fprintf(os.Stderr, "error: reading %s: %v\n", path, readErr)
		return 2
	}
	names := make([]string, len(picked))
	for i, c := range picked {
		names[i] = c.plugin
	}
	updated, added, err := addRequiredPlugins(string(orig), names)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\nAdd this to %s yourself:\n\n  plugins:\n    required:\n%s", err, path, yamlItems(names, "      "))
		return 2
	}
	if len(added) == 0 {
		fmt.Println("Already on: nothing to change.")
		return 0
	}
	if dry {
		fmt.Print(updated)
		return 0
	}
	if err := os.WriteFile(path, []byte(updated), 0o644); err != nil { //nolint:gosec // project config is world-readable by design
		fmt.Fprintf(os.Stderr, "error: writing %s: %v\n", path, err)
		return 2
	}
	// Prove the edit by reading it back the way a scan will, and undo it if the
	// scan would not see what was just written.
	cfg, lerr := core.LoadScanConfig(dir)
	for _, n := range added {
		if lerr != nil || cfg == nil || !projectEnablesPlugin(cfg.Plugins.Required, n) {
			restoreConfig(path, orig, existed)
			fmt.Fprintf(os.Stderr, "error: %s was not valid after the edit (%v); left unchanged\n", path, lerr)
			return 2
		}
	}
	for _, c := range picked {
		fmt.Printf("Enabled %s: %s\n", c.slug, c.capability)
		if strings.Contains(c.capability, "network") {
			fmt.Println("  note: this check needs the network, so an offline scan will report it as not run.")
		}
	}
	fmt.Printf("Wrote %s. Commit it so every scan of this repository runs the same checks.\n", path)
	return 0
}

func restoreConfig(path string, orig []byte, existed bool) {
	if existed {
		_ = os.WriteFile(path, orig, 0o644) //nolint:gosec // restoring the user's own file
		return
	}
	_ = os.Remove(path)
}

func yamlItems(names []string, indent string) string {
	var b strings.Builder
	for _, n := range names {
		b.WriteString(indent + "- " + n + "\n")
	}
	return b.String()
}

var (
	pluginsKeyRe  = regexp.MustCompile(`^plugins:\s*(#.*)?$`)
	requiredKeyRe = regexp.MustCompile(`^(\s+)required:\s*(#.*)?$`)
	requiredEmpty = regexp.MustCompile(`^(\s+)required:\s*\[\s*\]\s*(#.*)?$`)
	listItemRe    = regexp.MustCompile(`^(\s*)-\s`)
)

// addRequiredPlugins splices names into plugins.required without re-encoding
// the file, so comments and formatting survive. It returns the new text and the
// names actually added. A shape it does not recognise (flow style, anchors) is
// an error, never a guess.
func addRequiredPlugins(src string, names []string) (updated string, added []string, err error) {
	req := parseRequired(src)
	var add []string
	for _, n := range names {
		if !projectEnablesPlugin(req, n) {
			add = append(add, n)
		}
	}
	if len(add) == 0 {
		return src, nil, nil
	}
	lines := strings.Split(strings.TrimRight(src, "\n"), "\n")
	if strings.TrimSpace(src) == "" {
		lines = nil
	}
	pi := -1
	for i, l := range lines {
		if pluginsKeyRe.MatchString(l) {
			pi = i
		} else if strings.HasPrefix(l, "plugins:") {
			return "", nil, errors.New("plugins: in .nox.yaml is not in block style")
		}
	}
	if pi < 0 {
		lines = append(lines, "plugins:", "  required:")
		lines = append(lines, strings.Split(strings.TrimRight(yamlItems(add, "    "), "\n"), "\n")...)
		return strings.Join(lines, "\n") + "\n", add, nil
	}
	end := len(lines)
	for i := pi + 1; i < len(lines); i++ {
		t := strings.TrimSpace(lines[i])
		if t != "" && !strings.HasPrefix(t, "#") && !strings.HasPrefix(lines[i], " ") && !strings.HasPrefix(lines[i], "\t") {
			end = i
			break
		}
	}
	return spliceInPlugins(lines, pi, end, add)
}

func spliceInPlugins(lines []string, pi, end int, add []string) (updated string, added []string, err error) {
	for i := pi + 1; i < end; i++ {
		if requiredEmpty.MatchString(lines[i]) {
			ind := requiredEmpty.FindStringSubmatch(lines[i])[1]
			head := ind + "required:"
			out := append(append(append([]string{}, lines[:i]...), head), strings.Split(strings.TrimRight(yamlItems(add, ind+"  "), "\n"), "\n")...)
			return strings.Join(append(out, lines[i+1:]...), "\n") + "\n", add, nil
		}
		m := requiredKeyRe.FindStringSubmatch(lines[i])
		if m == nil {
			if strings.HasPrefix(strings.TrimSpace(lines[i]), "required:") {
				return "", nil, errors.New("plugins.required in .nox.yaml is not in block style")
			}
			continue
		}
		last, itemIndent := i, m[1]+"  "
		for j := i + 1; j < end; j++ {
			t := strings.TrimSpace(lines[j])
			if t == "" || strings.HasPrefix(t, "#") {
				continue
			}
			li := listItemRe.FindStringSubmatch(lines[j])
			if li == nil {
				break
			}
			last, itemIndent = j, li[1]
		}
		ins := strings.Split(strings.TrimRight(yamlItems(add, itemIndent), "\n"), "\n")
		out := append(append(append([]string{}, lines[:last+1]...), ins...), lines[last+1:]...)
		return strings.Join(out, "\n") + "\n", add, nil
	}
	ins := append([]string{"  required:"}, strings.Split(strings.TrimRight(yamlItems(add, "    "), "\n"), "\n")...)
	out := append(append(append([]string{}, lines[:pi+1]...), ins...), lines[pi+1:]...)
	return strings.Join(out, "\n") + "\n", add, nil
}

// parseRequired reads plugins.required from raw text through the same loader a
// scan uses, so "already on" agrees with what a scan would do.
func parseRequired(src string) []string {
	dir, err := os.MkdirTemp("", "nox-enable-*")
	if err != nil {
		return nil
	}
	defer func() { _ = os.RemoveAll(dir) }()
	if os.WriteFile(filepath.Join(dir, ".nox.yaml"), []byte(src), 0o600) != nil {
		return nil
	}
	return requiredPluginsForDir(dir)
}
