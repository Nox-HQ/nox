package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/nox-hq/nox-core/evidence"
	"github.com/nox-hq/nox/core/attack"
	mcpclient "go.klarlabs.de/mcp/client"
)

const attackMCPUsage = `Usage: nox attack mcp (--command|--url|--addr) <target> [flags]

  Validate an MCP server's tool manifest against the MCP scenario library:
  tool poisoning, description-borne exfiltration instructions, and cross-server
  trust redirection.

  nox INJECTS NOTHING here. It captures what the server advertises and inspects
  the tool descriptions the consuming agent would treat as trusted context. A
  confirmed finding is about the SERVED MANIFEST — "this server serves a
  poisoned description" — never a demonstration that an agent obeyed it.

  Capturing the manifest connects to the server (spawning its subprocess for
  stdio, or dialing it for http/grpc) and speaks MCP to it, so this is ACTIVE:
  it requires --authorize under every profile but safe, even though no attack
  payload is sent. Run only servers you are willing to reach.

Transports (choose one):
  --command <cmd>    stdio: server launch command, e.g. "node server.js"
  --url <url>        http: Streamable HTTP base URL, e.g. http://127.0.0.1:8080 (/mcp is appended)
  --addr <host:port> grpc: a gRPC MCP server, e.g. 127.0.0.1:50051

Flags:
  --dir <path>       stdio only: working directory for the server subprocess
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
		url         string
		addr        string
		dir         string
		profileName string
		samples     int
		timeout     time.Duration
		output      string
		authorize   bool
	)
	fs.StringVar(&command, "command", "", "stdio: server launch command")
	fs.StringVar(&url, "url", "", "http: Streamable HTTP MCP endpoint")
	fs.StringVar(&addr, "addr", "", "grpc: host:port of a gRPC MCP server")
	fs.StringVar(&dir, "dir", "", "stdio: working directory for the server subprocess")
	fs.StringVar(&profileName, "profile", string(attack.ProfileSandbox), "safety profile")
	fs.IntVar(&samples, "samples", 2, "manifest captures for the determinism gate")
	fs.DurationVar(&timeout, "timeout", 15*time.Second, "per-request MCP timeout")
	fs.StringVar(&output, "output", mcpTracePath, "write the traces here")
	fs.BoolVar(&authorize, "authorize", false, "acknowledge you are authorized to run and inspect the server")
	fs.Usage = func() { fmt.Fprint(os.Stderr, attackMCPUsage) }
	if err := fs.Parse(args); err != nil {
		return 2
	}

	src, transportName, err := mcpSourceFor(command, url, addr, dir, timeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
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

	fmt.Printf("nox attack mcp — ACTIVE, capturing over %s: %s\n", transportName, src.Name())
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

// mcpSourceFor selects a manifest source from exactly one transport flag. The
// three transports (stdio, Streamable HTTP, gRPC) all resolve to the same mcp
// client, so capture and inspection are identical regardless of how nox reached
// the server.
func mcpSourceFor(command, url, addr, dir string, timeout time.Duration) (attack.ManifestSource, string, error) {
	set := 0
	for _, v := range []string{command, url, addr} {
		if v != "" {
			set++
		}
	}
	switch {
	case set == 0:
		return nil, "", fmt.Errorf("choose one transport: --command (stdio), --url (http), or --addr (grpc)")
	case set > 1:
		return nil, "", fmt.Errorf("choose only one of --command, --url, --addr")
	}

	switch {
	case command != "":
		return &mcpClientSource{transport: "stdio", ref: command, dir: dir, timeout: timeout}, "stdio", nil
	case url != "":
		return &mcpClientSource{transport: "http", ref: url, timeout: timeout}, "http", nil
	default:
		return &mcpClientSource{transport: "grpc", ref: addr, timeout: timeout}, "grpc", nil
	}
}

// mcpClientSource captures an MCP manifest over one of the three client
// transports. It lives in the CLI, not core/attack, so the pure engine never
// dials a network or spawns a process — the same edge where the wall-clock
// clock and canary planting live.
type mcpClientSource struct {
	transport string // stdio | http | grpc
	ref       string // command line, URL, or host:port
	dir       string // stdio working directory
	timeout   time.Duration
}

// Name implements attack.ManifestSource.
func (s *mcpClientSource) Name() string { return s.ref }

// Capture dials the server over the chosen transport, initializes, lists tools,
// and projects them onto the attack engine's neutral manifest shape.
func (s *mcpClientSource) Capture(ctx context.Context) (attack.MCPManifest, error) {
	c, err := s.connect(ctx)
	if err != nil {
		return attack.MCPManifest{}, err
	}
	defer func() { _ = c.Close() }()

	info, err := c.Initialize(ctx)
	if err != nil {
		return attack.MCPManifest{}, fmt.Errorf("initialize: %w", err)
	}
	tools, err := c.ListTools(ctx)
	if err != nil {
		return attack.MCPManifest{}, fmt.Errorf("tools/list: %w", err)
	}

	out := attack.MCPManifest{}
	if info != nil {
		out.ServerName = info.Name
		out.ServerVersion = info.Version
	}
	for _, t := range tools {
		out.Tools = append(out.Tools, attack.MCPTool{
			Name:        t.Name,
			Description: t.Description,
			Server:      out.ServerName,
		})
	}
	return out, nil
}

// connect builds the mcp client for the chosen transport. gRPC has no client
// transport in the mcp library, so nox supplies one (see attack_mcp_grpc.go).
func (s *mcpClientSource) connect(ctx context.Context) (*mcpclient.Client, error) {
	switch s.transport {
	case "stdio":
		fields := strings.Fields(s.ref)
		if len(fields) == 0 {
			return nil, fmt.Errorf("empty stdio command")
		}
		tr, err := mcpclient.NewStdioTransport(fields[0], fields[1:]...)
		if err != nil {
			return nil, fmt.Errorf("stdio transport: %w", err)
		}
		return mcpclient.New(tr), nil
	case "http":
		tr, err := mcpclient.NewHTTPTransport(s.ref, mcpclient.WithRequestTimeout(s.timeout))
		if err != nil {
			return nil, fmt.Errorf("http transport: %w", err)
		}
		return mcpclient.New(tr), nil
	case "grpc":
		tr, err := dialGRPCTransport(ctx, s.ref)
		if err != nil {
			return nil, err
		}
		return mcpclient.New(tr), nil
	default:
		return nil, fmt.Errorf("unknown transport %q", s.transport)
	}
}
