package server

import mcp "go.klarlabs.de/mcp"

// Every registered tool states what it does to the world through MCP tool
// annotations, so a client can decide what to ask a person about without
// calling it. The default a missing annotation falls back to, per the MCP
// specification, is the worst case (destructive, open-world), which is the
// wrong thing to say about a read-only tool and says nothing useful about a
// mutating one. The read-only tools declare themselves through ReadOnly() and
// ClosedWorld()/OpenWorld() at their registration; the two shapes of mutating
// tool are here.

func hint(v bool) *bool { return &v }

var (
	// additiveLocalWrite is a tool that adds to a local file and never removes
	// or overwrites an entry (baseline_add, baseline_add_many).
	additiveLocalWrite = mcp.ToolAnnotations{
		ReadOnlyHint:    hint(false),
		DestructiveHint: hint(false),
		IdempotentHint:  hint(true),
		OpenWorldHint:   hint(false),
	}

	// pluginInstallHints is plugin_install: it fetches a binary over the network
	// and registers code that will run on the operator's machine, replacing an
	// earlier install of the same plugin, so it is destructive in the
	// specification's sense (an update that overwrites) and open-world. Installing
	// the same plugin twice leaves the same state, so it is idempotent.
	pluginInstallHints = mcp.ToolAnnotations{
		ReadOnlyHint:    hint(false),
		DestructiveHint: hint(true),
		IdempotentHint:  hint(true),
		OpenWorldHint:   hint(true),
	}
)
