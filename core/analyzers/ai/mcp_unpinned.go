package ai

import (
	"encoding/json"
	"regexp"
	"strings"
)

// MCP-025: an MCP server launched through a package runner without a pinned
// version.
//
// `npx -y @scope/server` resolves the registry's CURRENT release every time the
// host starts the server, and `-y` answers the install prompt on the user's
// behalf. Whatever was reviewed on the day the entry was added is not what runs
// on the day after the maintainer's account is taken over; that is the MCP04
// supply-chain path, and it needs no change to the repository to trigger. An
// exact version (`@scope/server@2025.1.14`) removes the window; a lockfile or
// digest would close it fully, but a version is the part a config file can say.
//
// This is not MCP-015. mcppin hashes the server DEFINITION (command, args, env)
// and flags it when that changes after approval. An unpinned package leaves the
// definition byte-identical while the code behind it changes, which is exactly
// what a definition hash cannot see.

var (
	mcpCommandRe = regexp.MustCompile(`(?i)"command"\s*:\s*"([^"]*)"`)
	mcpArgsRe    = regexp.MustCompile(`(?is)"args"\s*:\s*(\[[^\]]*\])`)
	// exactVersionRe is a concrete release: 1.2.3, 2025.1.14, 1.0.0-rc.1.
	exactVersionRe = regexp.MustCompile(`^v?\d+(?:\.\d+)+(?:[-+][0-9A-Za-z.-]+)?$`)
)

// packageRunners are the commands that fetch a package from a registry and run
// it. `node`, `python`, a bare binary or `docker` are not in the list: they run
// what is already on disk (or, for docker, are image pinning's concern).
var packageRunners = map[string]bool{"npx": true, "pnpx": true, "bunx": true, "uvx": true, "pipx": true}

// packageFlagsWithValue are runner flags whose NEXT argument is the package.
var packageFlagsWithValue = map[string]bool{"-p": true, "--package": true, "--from": true}

// mcpServerIsUnpinned is the validate hook for MCP-025. The match is one
// server's command and args; the verdict is whether the package it runs names
// an exact version.
func mcpServerIsUnpinned(match string) bool {
	cm := mcpCommandRe.FindStringSubmatch(match)
	am := mcpArgsRe.FindStringSubmatch(match)
	if cm == nil || am == nil {
		return false
	}
	// `npx.cmd`, `/usr/local/bin/npx`: the runner is the last path element.
	runner := strings.ToLower(cm[1])
	runner = runner[strings.LastIndexAny(runner, `/\`)+1:]
	runner = strings.TrimSuffix(runner, ".cmd")
	runner = strings.TrimSuffix(runner, ".exe")
	if !packageRunners[runner] {
		return false
	}
	var args []string
	if err := json.Unmarshal([]byte(am[1]), &args); err != nil {
		return false
	}
	pkg, ok := packageArgument(args)
	if !ok {
		return false
	}
	return !packageIsPinned(pkg)
}

// packageArgument picks the package out of a runner's arguments: the value of
// -p/--package/--from when given, otherwise the first argument that is not a
// flag. The second return is false when there is none (`npx --help`).
func packageArgument(args []string) (string, bool) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if packageFlagsWithValue[a] {
			if i+1 < len(args) {
				return args[i+1], true
			}
			return "", false
		}
		if v, ok := strings.CutPrefix(a, "--package="); ok {
			return v, true
		}
		if v, ok := strings.CutPrefix(a, "--from="); ok {
			return v, true
		}
		if strings.HasPrefix(a, "-") {
			continue
		}
		return a, true
	}
	return "", false
}

// packageIsPinned reports whether a package specifier names an exact version:
// npm's `name@1.2.3` / `@scope/name@1.2.3`, or pip's `name==1.2.3` /
// `name@1.2.3`. A dist-tag (`@latest`, `@next`), a range (`^1.2`, `~1`, `1.x`,
// `>=1`) and no version at all are all "whatever the registry says today".
func packageIsPinned(spec string) bool {
	if name, v, ok := strings.Cut(spec, "=="); ok && name != "" {
		return exactVersionRe.MatchString(v)
	}
	at := strings.LastIndex(spec, "@")
	if at <= 0 { // no "@", or only the scope's leading one
		return false
	}
	return exactVersionRe.MatchString(spec[at+1:])
}
