package cli

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/nox-hq/nox/core"
	"github.com/nox-hq/nox/plugin"
)

// pluginPolicyAt reads the plugin trust policy a workspace declares in its
// .nox.yaml: the base policy, the per-plugin overrides, and whether track
// profiles are ignored. A workspace without a readable .nox.yaml gets the
// strict default. Scans and `nox serve --plugins` both read it here, so an
// agent calling a plugin through MCP is held to the policy a scan of the same
// workspace would apply.
func pluginPolicyAt(target string) (policy, overrides plugin.Policy, ignoreTrackProfiles bool) {
	policy = plugin.DefaultPolicy()
	if cfg, err := plugin.LoadConfig(filepath.Join(core.ConfigRoot(target), ".nox.yaml")); err == nil {
		policy = plugin.ToPolicy(&cfg.PluginPolicy)
		overrides = plugin.Overrides(&cfg.PluginPolicy)
		ignoreTrackProfiles = cfg.PluginPolicy.IgnoreTrackProfiles
	}
	return policy, overrides, ignoreTrackProfiles
}

// servePluginHost starts a plugin host for `nox serve --plugins`, or returns
// nil when the flag is off.
//
// Hosting is opt-in. With a host attached the MCP server offers plugin.list
// and plugin.call_tool, and a call starts a plugin subprocess on the agent's
// behalf; the operator chooses that, the agent does not. The plugins hosted are
// every installed one, each passing the checks a scan applies before it runs
// one: the binary exists, matches the digest recorded at install, and its
// track's safety profile is enforced under the policy configRoot's .nox.yaml
// declares. A plugin that fails any of them is returned as a warning and the
// rest are still hosted.
func servePluginHost(ctx context.Context, enabled bool, configRoot string) (*plugin.Host, []string, error) {
	if !enabled {
		return nil, nil, nil
	}
	st, err := LoadState(DefaultStatePath())
	if err != nil {
		return nil, nil, fmt.Errorf("loading plugin state: %w", err)
	}
	names := make([]string, 0, len(st.Plugins))
	for i := range st.Plugins {
		names = append(names, st.Plugins[i].Name)
	}
	binaries, unusable, err := installedPluginBinaries(names)
	if err != nil {
		return nil, nil, err
	}

	var warnings []string
	for _, d := range unusable {
		if !d.Advisory {
			// The checks are worded for a scan's plugins.required; here
			// every installed plugin is asked for, so "required" misleads.
			warnings = append(warnings, strings.TrimPrefix(d.Detail, "required "))
		}
	}

	policy, overrides, ignoreTrackProfiles := pluginPolicyAt(configRoot)
	host := plugin.NewHost(
		plugin.WithPolicy(&policy),
		plugin.WithPolicyOverrides(&overrides),
		plugin.WithIgnoreTrackProfiles(ignoreTrackProfiles),
	)
	for _, bin := range binaries {
		if regErr := host.RegisterBinaryWithTrack(ctx, bin.path, nil, bin.track); regErr != nil {
			warnings = append(warnings, fmt.Sprintf("plugin %q was not hosted: %v", bin.name, regErr))
		}
	}
	return host, warnings, nil
}
