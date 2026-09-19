package server

import (
	"context"
	"encoding/json"

	"go.klarlabs.de/mcp"
	"go.klarlabs.de/mcp/protocol"
)

// The MCP server is driven by an agent, and an agent in a loop does not get
// tired. These limits exist for that case: not to ration a well-behaved client,
// but to stop a runaway or steered one from turning the user's machine into a
// scanning farm. Stdio carries exactly one client, so each tier is a single
// shared bucket; there is nobody else's budget to protect.
//
// Two tiers, because one flat limit would be wrong in both directions. Reading
// results back (list_findings, get_finding_detail, resources/read) is cheap and
// agents legitimately burst it while triaging, so a limit tight enough to matter
// for scans would stall ordinary use. Scanning walks a tree and burns CPU, so a
// limit loose enough for triage would not bound it at all.
const (
	// requestRate is the ceiling on every request. Well above any plausible
	// interactive use; it only binds on a loop.
	requestRate  = 20
	requestBurst = 50

	// costlyRate bounds the tools that do real work per call. A scan takes
	// seconds anyway, so one a second with a small burst never binds on an agent
	// that waits for its result, and caps one that does not.
	costlyRate  = 1
	costlyBurst = 3
)

// costlyTools are the tools whose cost scales with the workspace or reaches
// outside the process: scan and diff walk the tree, plugin.call_tool runs a
// plugin binary, plugin_install fetches one. Everything else reads state a scan
// already produced.
var costlyTools = map[string]bool{
	"scan":             true,
	"diff":             true,
	"plugin.call_tool": true,
	"plugin_install":   true,
}

// rateLimits returns the middleware chain enforcing both tiers.
func rateLimits() []mcp.Middleware {
	shared := func(*protocol.Request) string { return "stdio" }
	return []mcp.Middleware{
		mcp.RateLimit(requestRate, requestBurst, mcp.WithRateLimitKeyFunc(shared)),
		onlyFor(isCostlyCall, mcp.RateLimit(costlyRate, costlyBurst, mcp.WithRateLimitKeyFunc(shared))),
	}
}

// onlyFor applies m to the requests pred selects and passes the rest straight
// through, so a cheap call never spends a costly token.
func onlyFor(pred func(*protocol.Request) bool, m mcp.Middleware) mcp.Middleware {
	return func(next mcp.MiddlewareHandlerFunc) mcp.MiddlewareHandlerFunc {
		limited := m(next)
		return func(ctx context.Context, req *protocol.Request) (*protocol.Response, error) {
			if pred(req) {
				return limited(ctx, req)
			}
			return next(ctx, req)
		}
	}
}

func isCostlyCall(req *protocol.Request) bool {
	if req.Method != "tools/call" {
		return false
	}
	var p struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(req.Params, &p); err != nil {
		// A call we cannot read the name of is charged as costly: the handler
		// will reject it anyway, and an unreadable request is not a reason to
		// skip the tighter bucket.
		return true
	}
	return costlyTools[p.Name]
}
