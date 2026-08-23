package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/nox-hq/nox/core/attack"
	"github.com/nox-hq/nox/core/evidence"
	"github.com/nox-hq/nox/core/mcpdrift"
)

const attackMCPUsage = `Usage: nox attack mcp --command "<server launch command>" [flags]

  Validate an MCP server's tool manifest against the MCP scenario library:
  tool poisoning, description-borne exfiltration instructions, and cross-server
  trust redirection.

  nox INJECTS NOTHING here. It captures what the server advertises and inspects
  the tool descriptions the consuming agent would treat as trusted context. A
  confirmed finding is about the SERVED MANIFEST — "this server serves a
  poisoned description" — never a demonstration that an agent obeyed it.

  Capturing the manifest launches the server subprocess and speaks MCP to it, so
  this is ACTIVE: it requires --authorize under every profile but safe, even
  though no attack payload is sent. Run only servers you are willing to execute.

Flags:
  --command <cmd>    server launch command, e.g. "node server.js" (required)
  --dir <path>       working directory for the server subprocess
  --profile <name>   sandbox | staging | authorized-live (default sandbox)
  --samples <n>      manifest captures for the determinism gate (default 2)
  --timeout <dur>    per-request MCP timeout (default 15s)
  --output <path>    write the traces here (default attack.mcp.json)
  --authorize        REQUIRED for any profile other than safe

Exit: 0 = nothing confirmed, 1 = at least one CONFIRMED poisoned description, 2 = error.
`

// mcpTracePath is where MCP validation traces are written by default.
const mcpTracePath = "attack.mcp.json"

func runAttackMCP(args []string) int {
	fs := flag.NewFlagSet("attack mcp", flag.ContinueOnError)
	var (
		command     string
		dir         string
		profileName string
		samples     int
		timeout     time.Duration
		output      string
		authorize   bool
	)
	fs.StringVar(&command, "command", "", "server launch command (required)")
	fs.StringVar(&dir, "dir", "", "working directory for the server subprocess")
	fs.StringVar(&profileName, "profile", string(attack.ProfileSandbox), "safety profile")
	fs.IntVar(&samples, "samples", 2, "manifest captures for the determinism gate")
	fs.DurationVar(&timeout, "timeout", 15*time.Second, "per-request MCP timeout")
	fs.StringVar(&output, "output", mcpTracePath, "write the traces here")
	fs.BoolVar(&authorize, "authorize", false, "acknowledge you are authorized to run and inspect the server")
	fs.Usage = func() { fmt.Fprint(os.Stderr, attackMCPUsage) }
	if err := fs.Parse(args); err != nil {
		return 2
	}

	if command == "" {
		fmt.Fprintln(os.Stderr, "error: --command is required")
		fs.Usage()
		return 2
	}

	profile, err := attack.ParseProfile(profileName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}
	if profile.RequiresAuthorization() && !authorize {
		fmt.Fprintln(os.Stderr, "error: capturing an MCP server runs its subprocess and speaks MCP to it.")
		fmt.Fprintln(os.Stderr, "Pass --authorize to confirm you are willing to execute this server. Refusing to run.")
		return 2
	}

	src := &mcpCaptureSource{
		command: strings.Fields(command),
		dir:     dir,
		timeout: timeout,
	}

	fmt.Printf("nox attack mcp — ACTIVE, capturing %s\n", command)
	res, err := attack.RunMCP(context.Background(), src, attack.MCPRunConfig{
		Profile:    profile,
		Authorized: authorize,
		Samples:    samples,
		Now:        time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: mcp validation failed: %v\n", err)
		return 2
	}

	raw, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: marshalling result: %v\n", err)
		return 2
	}
	if err := os.WriteFile(output, append(raw, '\n'), 0o644); err != nil { //nolint:gosec // trace artifact, not a secret
		fmt.Fprintf(os.Stderr, "error: writing %s: %v\n", output, err)
		return 2
	}

	printMCPSummary(res, output)
	return res.ExitCode()
}

// printMCPSummary renders MCP traces, keeping the manifest-vs-agent distinction
// visible so a confirmed poisoned description is never misread as a confirmed
// agent compromise.
func printMCPSummary(r *attack.Result, output string) {
	if !r.ControlSound {
		fmt.Println("\n  !! a scenario's patterns matched the benign control; nothing is confirmed for it.")
	}
	confirmed := 0
	for i := range r.Traces {
		t := r.Traces[i]
		if t.Exploitability == evidence.Confirmed {
			confirmed++
		}
		fmt.Printf("\n  %s  %s\n", t.ScenarioID, t.Exploitability)
		fmt.Printf("    %s\n", evidence.Describe(t.Exploitability))
		if t.Evidence != nil {
			fmt.Printf("    tool     : %s\n", t.Evidence.Field)
			fmt.Printf("    class    : %s\n", t.Evidence.Signal)
			fmt.Printf("    served   : %s\n", t.Evidence.Response)
		}
		if t.Classification.CVSSVector != "" {
			fmt.Printf("    standards: %s / %s / %s   score=%.1f %s\n",
				t.Classification.OWASPASI, t.Classification.OWASPLLM, t.Classification.CWE,
				t.Classification.Score, t.Classification.Severity)
		}
		if t.Note != "" {
			fmt.Printf("    note     : %s\n", t.Note)
		}
	}
	fmt.Printf("\n  %d confirmed poisoned description(s)\n", confirmed)
	fmt.Printf("[attack] wrote %s\n", output)
}

// mcpCaptureSource adapts core/mcpdrift's live capture to the attack engine's
// ManifestSource. It lives in the CLI, not core/attack, so the pure engine
// never depends on subprocess spawning — the same edge where the wall-clock
// clock and canary planting live.
type mcpCaptureSource struct {
	command []string
	dir     string
	timeout time.Duration
}

// Name implements attack.ManifestSource.
func (s *mcpCaptureSource) Name() string { return strings.Join(s.command, " ") }

// Capture implements attack.ManifestSource by driving one MCP capture and
// projecting mcpdrift's manifest onto the attack engine's neutral shape.
func (s *mcpCaptureSource) Capture(ctx context.Context) (attack.MCPManifest, error) {
	m, err := mcpdrift.CaptureManifest(ctx, mcpdrift.CaptureOptions{
		Command: s.command,
		Dir:     s.dir,
		Timeout: s.timeout,
	})
	if err != nil {
		return attack.MCPManifest{}, err
	}
	tools := make([]attack.MCPTool, 0, len(m.Tools))
	for _, t := range m.Tools {
		tools = append(tools, attack.MCPTool{
			Name:        t.Name,
			Description: t.Description,
			Server:      m.ServerName,
		})
	}
	return attack.MCPManifest{
		ServerName:    m.ServerName,
		ServerVersion: m.ServerVersion,
		Tools:         tools,
	}, nil
}
