package ai

import (
	"encoding/json"
	"regexp"

	"github.com/nox-hq/nox/core/mcpconfig"
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
)

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
	if _, _, ok := mcpconfig.RunnerOf(cm[1]); !ok {
		return false
	}
	var args []string
	if err := json.Unmarshal([]byte(am[1]), &args); err != nil {
		return false
	}
	pkg, ok := mcpconfig.PackageArgument(args)
	if !ok {
		return false
	}
	return !mcpconfig.PackageIsPinned(pkg)
}
