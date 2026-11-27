package plugin

import (
	"fmt"
	"sort"
	"strings"
)

// WithOffline makes the host refuse every tool that declares a network host
// other than loopback. It is how `nox scan --offline` reaches plugins: the
// scan promises no outbound connection, and a plugin tool that declares
// api.anthropic.com is exactly one.
//
// The refusal reads the tool's declaration, which is all the host can read:
// plugin processes are not sandboxed, so a plugin that contacts a host it did
// not declare is not stopped here. Declaring is what the SDK asks of a plugin
// that calls out, and the safety policy already refuses undeclared hosts on
// tracks that list allowed ones.
func WithOffline(offline bool) HostOption {
	return func(h *Host) { h.offline = offline }
}

// OfflineEgressError is the refusal of a tool that declares network hosts
// under an offline scan. The plugin is not terminated: it did nothing wrong,
// and its other tools may be offline-safe.
type OfflineEgressError struct {
	Plugin string
	Tool   string
	Hosts  []string
}

func (e *OfflineEgressError) Error() string {
	return fmt.Sprintf("offline scan: tool %q declares network hosts (%s) and was not run",
		e.Tool, strings.Join(e.Hosts, ", "))
}

// Egress is one tool the host authorized that declares network hosts.
type Egress struct {
	Plugin string
	Tool   string
	Hosts  []string
}

// Egress returns the tools this host authorized that declare network hosts,
// in the order first authorized, each once.
func (h *Host) Egress() []Egress {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return append([]Egress(nil), h.egress...)
}

func (h *Host) recordEgress(pluginName, tool string, hosts []string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, e := range h.egress {
		if e.Plugin == pluginName && e.Tool == tool {
			return
		}
	}
	h.egress = append(h.egress, Egress{Plugin: pluginName, Tool: tool, Hosts: hosts})
}

// toolEgressHosts returns the non-loopback network hosts a tool declares,
// sorted: its own safety block when it has one, else the plugin's.
func toolEgressHosts(p *Plugin, toolName string) []string {
	safety := p.Info().Safety
	if ti := p.getToolInfo(toolName); ti != nil && ti.Safety != nil {
		safety = ti.Safety
	}
	var hosts []string
	for _, host := range safety.GetNetworkHosts() {
		if !isLoopbackHost(host) {
			hosts = append(hosts, host)
		}
	}
	sort.Strings(hosts)
	return hosts
}

func isLoopbackHost(host string) bool {
	switch strings.ToLower(strings.TrimSpace(host)) {
	case "localhost", "127.0.0.1", "::1", "[::1]":
		return true
	}
	return false
}
