package ai

import (
	"net/url"
	"path"
	"sort"
	"strings"
)

// An MCP client config does not list the tools a server exposes; the server
// does, when it runs. What the config does say is how the server is launched:
// a shell interpreter, a published package with a telling name, a remote URL.
// That is enough to say, by name and without guessing at tool lists, which
// capabilities the agent is being handed. The result feeds the same capability
// lattice a coded agent's tools do, so the graph weighs a configured shell
// server and a registered shell tool the same way.
//
// This is a reading of names. A server called "notes" that shells out is not
// seen, and a server with "fetch" in its name that only parses is over-read, so
// the tool "*" stays what it was (every tool the server exposes) and these tags
// are what the configuration shows, not a claim about the server's code.

// shellInterpreters are commands that are a shell: an MCP server launched
// through one runs whatever its arguments say.
var shellInterpreters = map[string]bool{
	"bash": true, "sh": true, "zsh": true, "fish": true, "dash": true, "ksh": true,
	"cmd": true, "cmd.exe": true, "powershell": true, "powershell.exe": true, "pwsh": true, "pwsh.exe": true,
}

// serverWordCaps maps a word in a server's command or package name to the
// capabilities such a server is known to hold.
var serverWordCaps = map[string][]CapabilityTag{
	"shell":      {CapShellExec},
	"terminal":   {CapShellExec},
	"bash":       {CapShellExec},
	"exec":       {CapShellExec},
	"filesystem": {CapFileRead, CapFileWrite},
	"fetch":      {CapHTTPRequest},
	"puppeteer":  {CapHTTPRequest},
	"playwright": {CapHTTPRequest},
	"browser":    {CapHTTPRequest},
	"postgres":   {CapDatabaseRead},
	"postgresql": {CapDatabaseRead},
	"mysql":      {CapDatabaseRead},
	"sqlite":     {CapDatabaseRead},
	"mongodb":    {CapDatabaseRead},
	"slack":      {CapWebhookPost},
	"discord":    {CapWebhookPost},
	"smtp":       {CapEmailSend},
	"gmail":      {CapEmailSend},
}

// mcpServerCapabilities returns the capability tags the launch configuration of
// an MCP server shows, sorted. Environment values are never read: they hold
// credentials and say nothing about capability.
func mcpServerCapabilities(command string, args []string, rawURL string) []string {
	set := map[CapabilityTag]bool{}
	if shellInterpreters[strings.ToLower(path.Base(strings.ReplaceAll(command, "\\", "/")))] {
		set[CapShellExec] = true
	}
	if rawURL != "" {
		set[CapHTTPRequest] = true
	}
	for _, field := range append([]string{command}, args...) {
		if strings.HasPrefix(field, "-") {
			continue
		}
		for _, w := range nameWords(field) {
			for _, c := range serverWordCaps[w] {
				set[c] = true
			}
		}
	}
	out := make([]string, 0, len(set))
	for c := range set {
		out = append(out, string(c))
	}
	sort.Strings(out)
	return out
}

// nameWords splits a command or package name into lower-case words:
// "@modelcontextprotocol/server-filesystem" becomes modelcontextprotocol,
// server, filesystem.
func nameWords(s string) []string {
	return strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < '0' || r > '9')
	})
}

// mcpTransport says how the agent reaches a server: "remote" for a URL,
// "stdio" for a launched process, "" when the definition says neither.
func mcpTransport(command, rawURL string) string {
	switch {
	case rawURL != "":
		return "remote"
	case command != "":
		return "stdio"
	}
	return ""
}

// mcpEndpoint is a remote server's address with anything that could carry a
// credential removed: user info and the query string.
func mcpEndpoint(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host + u.Path
}
