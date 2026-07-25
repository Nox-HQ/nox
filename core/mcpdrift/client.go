// Package mcpdrift captures a reviewable baseline of an MCP server's tool
// manifest and detects drift (a "rug-pull") against it. It speaks just enough
// of the Model Context Protocol over stdio to launch a server, initialize, and
// read its full tool list — then serializes that as diffable local data.
//
// The premise: the only safe on-device "learning" is a local, reviewable
// baseline of your environment, with drift surfaced as a finding — no mutating
// detection logic, no private brain. The baseline is data you can diff, commit,
// and review in a PR.
//
// SECURITY: capturing a manifest launches the user-provided server as a
// subprocess. A malicious MCP server must NEVER be run un-sandboxed — its
// process can open sockets or tamper with the host. Callers are responsible for
// isolation (container with no network, read-only FS, dropped capabilities, or
// an OS sandbox). This package only speaks the protocol; it does not sandbox.
package mcpdrift

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"sync"
	"time"
)

// defaultTimeout bounds every request. A server that never answers must not
// hang the capture forever.
const defaultTimeout = 15 * time.Second

// protocolVersion is the MCP revision this client negotiates. It matches the
// revision nox serve and the reference SDKs speak over stdio.
const protocolVersion = "2024-11-05"

// clientName / clientVersion identify this client in the initialize handshake.
const (
	clientName    = "nox-mcp-drift"
	clientVersion = "1.0.0"
)

// jsonRPCRequest is an outbound JSON-RPC 2.0 request or notification. A
// notification omits ID (pointer left nil).
type jsonRPCRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      *int   `json:"id,omitempty"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

// jsonRPCResponse is an inbound JSON-RPC 2.0 response.
type jsonRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      *int            `json:"id,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *jsonRPCError   `json:"error,omitempty"`
}

type jsonRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// CaptureOptions configures a manifest capture.
type CaptureOptions struct {
	// Command is the server launch command: argv[0] is the executable, the
	// rest are arguments. Required.
	Command []string
	// Dir is the working directory for the subprocess. Empty means inherit.
	Dir string
	// Env is the subprocess environment. Nil means inherit the parent's.
	Env []string
	// Timeout bounds each JSON-RPC request. Zero uses defaultTimeout.
	Timeout time.Duration
}

// stdioClient drives one MCP server subprocess over stdio. It is single-shot:
// start, capture, close.
type stdioClient struct {
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	timeout time.Duration

	mu        sync.Mutex
	nextID    int
	responses map[int]chan jsonRPCResponse
	readErr   error
	closed    bool
}

// CaptureManifest launches the MCP server described by opts, performs the
// initialize handshake, and reads its tool list. The returned Manifest is
// canonicalized (tools sorted by name, schemas re-serialized with sorted keys)
// so two captures of an unchanged server are byte-identical and produce no
// drift.
func CaptureManifest(ctx context.Context, opts CaptureOptions) (Manifest, error) {
	if len(opts.Command) == 0 {
		return Manifest{}, fmt.Errorf("mcpdrift: empty server command")
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}

	c := &stdioClient{
		nextID:    1,
		responses: make(map[int]chan jsonRPCResponse),
		timeout:   timeout,
	}
	if err := c.start(ctx, opts); err != nil {
		return Manifest{}, err
	}
	defer c.close()

	init, err := c.initialize(ctx)
	if err != nil {
		return Manifest{}, err
	}
	tools, err := c.listTools(ctx)
	if err != nil {
		return Manifest{}, err
	}

	return buildManifest(init, tools), nil
}

func (c *stdioClient) start(ctx context.Context, opts CaptureOptions) error {
	//nolint:gosec // The server command is operator-supplied by design; this is
	// a tool that inspects a user-named MCP server. Isolation is the caller's
	// responsibility and is documented on the package and command.
	cmd := exec.CommandContext(ctx, opts.Command[0], opts.Command[1:]...)
	cmd.Dir = opts.Dir
	cmd.Env = opts.Env

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("mcpdrift: stdin pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("mcpdrift: stdout pipe: %w", err)
	}
	// Drain stderr so a chatty server does not block on a full pipe buffer.
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("mcpdrift: stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("mcpdrift: starting server %q: %w", opts.Command[0], err)
	}
	c.cmd = cmd
	c.stdin = stdin

	go c.readLoop(stdout)
	go drain(stderr)
	return nil
}

// readLoop demultiplexes responses by JSON-RPC id. Notifications (no id) are
// dropped. It runs until stdout closes.
func (c *stdioClient) readLoop(stdout io.Reader) {
	scanner := bufio.NewScanner(stdout)
	// MCP messages can be large (full tool schemas); raise the line cap well
	// beyond the 64KiB default.
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var resp jsonRPCResponse
		if err := json.Unmarshal(line, &resp); err != nil {
			// A well-behaved server emits one JSON object per line. Skip
			// non-JSON noise rather than crashing the reader.
			continue
		}
		if resp.ID == nil {
			continue // server-originated notification
		}
		c.mu.Lock()
		ch, ok := c.responses[*resp.ID]
		if ok {
			delete(c.responses, *resp.ID)
		}
		c.mu.Unlock()
		if ok {
			ch <- resp
		}
	}
	c.mu.Lock()
	if err := scanner.Err(); err != nil {
		c.readErr = err
	}
	// Wake any pending waiters so they fail fast instead of blocking to timeout
	// when the server dies.
	for id, ch := range c.responses {
		close(ch)
		delete(c.responses, id)
	}
	c.closed = true
	c.mu.Unlock()
}

func drain(r io.Reader) {
	_, _ = io.Copy(io.Discard, r)
}

// request sends a JSON-RPC request and waits for the matching response.
func (c *stdioClient) request(ctx context.Context, method string, params any) (json.RawMessage, error) {
	c.mu.Lock()
	if c.closed {
		err := c.readErr
		c.mu.Unlock()
		if err != nil {
			return nil, fmt.Errorf("mcpdrift: server closed the stream: %w", err)
		}
		return nil, fmt.Errorf("mcpdrift: server closed the stream")
	}
	id := c.nextID
	c.nextID++
	ch := make(chan jsonRPCResponse, 1)
	c.responses[id] = ch
	c.mu.Unlock()

	if err := c.send(jsonRPCRequest{JSONRPC: "2.0", ID: &id, Method: method, Params: params}); err != nil {
		c.mu.Lock()
		delete(c.responses, id)
		c.mu.Unlock()
		return nil, err
	}

	timer := time.NewTimer(c.timeout)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("mcpdrift: %s cancelled: %w", method, ctx.Err())
	case <-timer.C:
		return nil, fmt.Errorf("mcpdrift: timeout waiting for response to %q", method)
	case resp, ok := <-ch:
		if !ok {
			return nil, fmt.Errorf("mcpdrift: server closed before answering %q", method)
		}
		if resp.Error != nil {
			return nil, fmt.Errorf("mcpdrift: %s returned JSON-RPC error %d: %s", method, resp.Error.Code, resp.Error.Message)
		}
		return resp.Result, nil
	}
}

// notify sends a JSON-RPC notification (no id, no response expected).
func (c *stdioClient) notify(method string, params any) error {
	return c.send(jsonRPCRequest{JSONRPC: "2.0", Method: method, Params: params})
}

func (c *stdioClient) send(req jsonRPCRequest) error {
	data, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("mcpdrift: marshalling %s: %w", req.Method, err)
	}
	data = append(data, '\n')
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, err := c.stdin.Write(data); err != nil {
		return fmt.Errorf("mcpdrift: writing %s to server: %w", req.Method, err)
	}
	return nil
}

// initializeResult holds the fields of the initialize response this client
// records in the manifest.
type initializeResult struct {
	ProtocolVersion string `json:"protocolVersion"`
	ServerInfo      struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"serverInfo"`
}

func (c *stdioClient) initialize(ctx context.Context) (initializeResult, error) {
	params := map[string]any{
		"protocolVersion": protocolVersion,
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": clientName, "version": clientVersion},
	}
	raw, err := c.request(ctx, "initialize", params)
	if err != nil {
		return initializeResult{}, err
	}
	var res initializeResult
	if err := json.Unmarshal(raw, &res); err != nil {
		return initializeResult{}, fmt.Errorf("mcpdrift: parsing initialize result: %w", err)
	}
	// The spec requires the client to acknowledge initialization before other
	// requests. Servers built on strict SDKs reject tools/list without it.
	if err := c.notify("notifications/initialized", map[string]any{}); err != nil {
		return initializeResult{}, err
	}
	return res, nil
}

// rawTool is a tool as it arrives on the wire, before canonicalization.
type rawTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

func (c *stdioClient) listTools(ctx context.Context) ([]rawTool, error) {
	raw, err := c.request(ctx, "tools/list", map[string]any{})
	if err != nil {
		return nil, err
	}
	var res struct {
		Tools []rawTool `json:"tools"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		return nil, fmt.Errorf("mcpdrift: parsing tools/list result: %w", err)
	}
	return res.Tools, nil
}

func (c *stdioClient) close() {
	c.mu.Lock()
	stdin := c.stdin
	c.mu.Unlock()
	if stdin != nil {
		_ = stdin.Close()
	}
	if c.cmd != nil && c.cmd.Process != nil {
		// Best-effort: closing stdin should let a stdio server exit; kill if not.
		done := make(chan struct{})
		go func() {
			_ = c.cmd.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			_ = c.cmd.Process.Kill()
			<-done
		}
	}
}
