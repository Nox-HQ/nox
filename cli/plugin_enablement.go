package main

import (
	"fmt"
	"strings"

	"github.com/nox-hq/nox/core"
)

// Installing a plugin does not make it run. `plugins.required` in the
// project's .nox.yaml is what enables it, and that separation is deliberate:
// nox's first design constraint is that the same inputs produce the same
// outputs with no hidden state, so a globally-installed plugin that ran
// automatically would make a scan's findings depend on which plugins happen to
// be present on the machine. Two developers on one repository would get
// different results.
//
// The price of that correctness is a silent dead end. `nox plugin install`
// succeeds, `nox plugin list` shows the plugin, `nox scan` reports nothing, and
// the natural reading is that the plugin found nothing rather than that it
// never ran. The helpers here exist so the CLI can say which of the two it is.
// See #376.

// projectEnablesPlugin reports whether name appears in a project's
// `plugins.required` list.
//
// Entries may carry a version constraint (`nox/reachability@>=0.5`), which is
// the form both the README and docs/marketplace.md show, so the constraint is
// stripped before comparing. Matching is exact on the remaining name — a
// project requiring `nox/reachability-extra` has not enabled
// `nox/reachability`.
func projectEnablesPlugin(required []string, name string) bool {
	name = strings.TrimSpace(name)
	if name == "" {
		return false
	}
	for _, spec := range required {
		if pluginNameFromSpec(spec) == name {
			return true
		}
	}
	return false
}

// pluginNameFromSpec strips a version constraint and surrounding whitespace
// from a `plugins.required` entry, leaving the bare plugin name.
func pluginNameFromSpec(spec string) string {
	spec = strings.TrimSpace(spec)
	if i := strings.Index(spec, "@"); i >= 0 {
		spec = spec[:i]
	}
	return strings.TrimSpace(spec)
}

// enablePluginHint returns the message shown after installing a plugin the
// current project does not require. It contains the literal YAML to add rather
// than a description of it — a hint that says "add it to your config" without
// saying what to write leaves the reader exactly where they were.
func enablePluginHint(name string) string {
	return fmt.Sprintf(`[note] %s is installed but not enabled for this project.
       Plugins run only when the project asks for them, so that a scan does
       not depend on what happens to be installed on the machine.
       Add it to .nox.yaml:

         plugins:
           required:
             - %s
`, name, name)
}

// requiredPluginsForDir loads the `plugins.required` list for a directory,
// returning nil when there is no config or it cannot be read. A hint or an
// ACTIVE column is advisory output; failing a command over it would be worse
// than omitting it.
func requiredPluginsForDir(dir string) []string {
	cfg, err := core.LoadScanConfig(dir)
	if err != nil || cfg == nil {
		return nil
	}
	return cfg.Plugins.Required
}
