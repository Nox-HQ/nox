package plugin

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"sync"
	"time"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/structpb"
)

// HostAPIVersion is the protocol version the host advertises during handshake.
const HostAPIVersion = "v1"

// pluginTokenEnv is the environment variable through which the host hands a
// per-launch shared secret to the plugin subprocess it spawns. A plugin binds
// an unauthenticated loopback gRPC port (see sdk.Serve); the token lets the
// plugin authenticate the one caller allowed to drive it — the host that
// launched it — and reject every other local process or LAN peer that connects
// to the port during a scan.
const pluginTokenEnv = "NOX_PLUGIN_TOKEN"

// pluginTokenMetaKey is the gRPC metadata key carrying the per-launch token on
// every RPC. It must match the key the SDK server checks.
const pluginTokenMetaKey = "x-nox-plugin-token"

// newLaunchToken returns a fresh 256-bit hex token. A crypto/rand failure is
// returned to the caller rather than swallowed: the host must not fall back to
// an unauthenticated channel.
func newLaunchToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// tokenUnaryInterceptor attaches the per-launch token to every outgoing RPC so
// the plugin can authenticate the caller as the host that spawned it.
func tokenUnaryInterceptor(token string) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		ctx = metadata.AppendToOutgoingContext(ctx, pluginTokenMetaKey, token)
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

// State represents the lifecycle state of a plugin connection.
type State int

// State constants for plugin lifecycle.
const (
	StateInit     State = iota // Created, not yet handshaken.
	StateReady                 // Handshake complete, ready for tool invocations.
	StateStopping              // Shutdown in progress.
	StateStopped               // Cleanly shut down.
	StateFailed                // Failed during handshake or runtime.
)

// Diagnostic is a non-finding message emitted by a plugin.
type Diagnostic struct {
	Severity string
	Message  string
	Source   string
}

// Info holds the parsed manifest from a plugin after handshake.
type Info struct {
	Name         string
	Version      string
	APIVersion   string
	Capabilities []CapabilityInfo
	Safety       *pluginv1.SafetyRequirements
}

// CapabilityInfo describes a named group of tools and resources.
type CapabilityInfo struct {
	Name        string
	Description string
	Tools       []ToolInfo
	Resources   []ResourceInfo
}

// ToolInfo describes a single invocable tool.
type ToolInfo struct {
	Name                string
	Description         string
	ReadOnly            bool
	RequiresScanContext bool
	// Safety, when non-nil, are this tool's own requirements, which override
	// the plugin-level block for invocations of this tool. Nil means the tool
	// inherits the plugin-level requirements — the behaviour of every plugin
	// built before ToolDef.safety existed.
	Safety *pluginv1.SafetyRequirements
}

// ResourceInfo describes a resource a plugin can serve.
type ResourceInfo struct {
	URITemplate string
	Name        string
	Description string
	MimeType    string
}

// Plugin manages a single gRPC connection to a plugin process.
// It acts as the entity for plugin lifecycle: init → ready → stopped.
type Plugin struct {
	info        Info
	state       State
	client      pluginv1.PluginServiceClient
	conn        *grpc.ClientConn
	cmd         *exec.Cmd // nil if connected to an external process
	rateLimiter *RateLimiter
	mu          sync.Mutex

	// policy is the effective policy for THIS plugin, resolved from its
	// registry track merged with the operator's overrides. Plugins of
	// different tracks run under different policies in the same host, so
	// enforcement reads this rather than a single host-wide value.
	policy Policy
}

// Policy returns the effective policy enforced against this plugin.
func (p *Plugin) Policy() Policy {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.policy
}

// setPolicy assigns the effective policy. Called by the host during
// registration, before the plugin can be invoked.
func (p *Plugin) setPolicy(pol Policy) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.policy = pol
}

// NewPlugin creates a Plugin from an existing gRPC client connection.
// The Plugin starts in StateInit and requires a Handshake call before
// tool invocation.
func NewPlugin(conn *grpc.ClientConn) *Plugin {
	return &Plugin{
		state:  StateInit,
		client: pluginv1.NewPluginServiceClient(conn),
		conn:   conn,
	}
}

// StartBinary spawns a plugin binary as a subprocess, reads the
// NOX_PLUGIN_ADDR=host:port line from its stdout, and establishes
// a gRPC connection. The returned Plugin is in StateInit.
func StartBinary(ctx context.Context, path string, args []string, timeout time.Duration) (*Plugin, error) {
	// Per-launch shared secret authenticating this host to the plugin it spawns.
	// Generated before the process starts so it can be passed in the child's
	// environment; a crypto/rand failure aborts the launch rather than falling
	// back to an unauthenticated channel.
	token, err := newLaunchToken()
	if err != nil {
		return nil, fmt.Errorf("generating plugin auth token: %w", err)
	}

	cmd := exec.CommandContext(ctx, path, args...)
	// Inherit the host environment and add the auth token. A foreign process
	// that later connects to the plugin's loopback port cannot read this child's
	// environment (on a correctly configured OS it is owner-only), so it cannot
	// present the token and is rejected by the plugin's server interceptor.
	cmd.Env = append(os.Environ(), pluginTokenEnv+"="+token)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("creating stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting plugin binary %s: %w", path, err)
	}

	addrCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	addr, err := waitForAddr(addrCtx, stdout)
	if err != nil {
		_ = cmd.Process.Kill()
		return nil, fmt.Errorf("waiting for plugin address: %w", err)
	}

	conn, err := grpc.NewClient(addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithUnaryInterceptor(tokenUnaryInterceptor(token)),
	)
	if err != nil {
		_ = cmd.Process.Kill()
		return nil, fmt.Errorf("dialing plugin at %s: %w", addr, err)
	}

	p := NewPlugin(conn)
	p.cmd = cmd
	return p, nil
}

// Handshake performs the GetManifest RPC and transitions the plugin to
// StateReady. It returns an error if the API version is incompatible
// or the RPC fails.
func (p *Plugin) Handshake(ctx context.Context, hostAPIVersion string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	resp, err := p.client.GetManifest(ctx, &pluginv1.GetManifestRequest{
		ApiVersion: hostAPIVersion,
	})
	if err != nil {
		p.state = StateFailed
		return fmt.Errorf("GetManifest RPC failed: %w", err)
	}

	if resp.GetApiVersion() != hostAPIVersion {
		p.state = StateFailed
		return fmt.Errorf("API version mismatch: host=%s plugin=%s", hostAPIVersion, resp.GetApiVersion())
	}

	p.info = parseManifest(resp)
	p.state = StateReady
	return nil
}

// Info returns the parsed plugin manifest. Only valid after a successful Handshake.
func (p *Plugin) Info() Info {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.info
}

// State returns the current plugin lifecycle state.
func (p *Plugin) State() State {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.state
}

// InvokeTool calls the plugin's InvokeTool RPC with the given tool name,
// input parameters, and workspace root.
func (p *Plugin) InvokeTool(ctx context.Context, toolName string, input map[string]any, workspaceRoot string) (*pluginv1.InvokeToolResponse, error) {
	p.mu.Lock()
	if p.state != StateReady {
		p.mu.Unlock()
		return nil, fmt.Errorf("plugin %q not ready (state=%d)", p.info.Name, p.state)
	}
	p.mu.Unlock()

	req, err := buildInvokeRequest(toolName, input, workspaceRoot)
	if err != nil {
		return nil, err
	}

	return p.client.InvokeTool(ctx, req)
}

// invokeRequest sends a pre-built request, applying the same readiness check
// as InvokeTool. Used by the post-scan path, whose request carries a
// ScanContext that buildInvokeRequest does not model.
func (p *Plugin) invokeRequest(ctx context.Context, req *pluginv1.InvokeToolRequest) (*pluginv1.InvokeToolResponse, error) {
	p.mu.Lock()
	if p.state != StateReady {
		p.mu.Unlock()
		return nil, fmt.Errorf("plugin %q not ready (state=%d)", p.info.Name, p.state)
	}
	p.mu.Unlock()

	return p.client.InvokeTool(ctx, req)
}

// fail transitions the plugin to StateFailed. Called by the violation handler
// before Close to mark the plugin as failed rather than cleanly stopped.
func (p *Plugin) fail() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.state != StateStopped && p.state != StateStopping {
		p.state = StateFailed
	}
}

// getToolInfo looks up a tool definition by name from the parsed manifest.
func (p *Plugin) getToolInfo(name string) *ToolInfo {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, cap := range p.info.Capabilities {
		for i, tool := range cap.Tools {
			if tool.Name == name {
				return &cap.Tools[i]
			}
		}
	}
	return nil
}

// HasTool reports whether this plugin declares a tool with the given name.
func (p *Plugin) HasTool(name string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, cap := range p.info.Capabilities {
		for _, tool := range cap.Tools {
			if tool.Name == name {
				return true
			}
		}
	}
	return false
}

// Close shuts down the gRPC connection and, if applicable, the subprocess.
// For subprocesses, it sends SIGTERM and waits up to 5 seconds before SIGKILL.
// Close is idempotent.
func (p *Plugin) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.state == StateStopped || p.state == StateStopping {
		return nil
	}
	wasFailed := p.state == StateFailed
	p.state = StateStopping

	var errs []error

	if p.conn != nil {
		if err := p.conn.Close(); err != nil {
			errs = append(errs, fmt.Errorf("closing gRPC connection: %w", err))
		}
	}

	if p.cmd != nil && p.cmd.Process != nil {
		// Send SIGTERM (on Unix) or kill on Windows.
		if err := p.cmd.Process.Signal(sigterm()); err != nil {
			// Process may have already exited.
			_ = p.cmd.Process.Kill()
		} else {
			done := make(chan error, 1)
			go func() { done <- p.cmd.Wait() }()

			select {
			case <-done:
				// Exited cleanly.
			case <-time.After(5 * time.Second):
				_ = p.cmd.Process.Kill()
				<-done
			}
		}
	}

	if wasFailed {
		p.state = StateFailed
	} else {
		p.state = StateStopped
	}
	return errors.Join(errs...)
}

// parseManifest extracts an Info from a GetManifestResponse.
func parseManifest(resp *pluginv1.GetManifestResponse) Info {
	info := Info{
		Name:       resp.GetName(),
		Version:    resp.GetVersion(),
		APIVersion: resp.GetApiVersion(),
		Safety:     resp.GetSafety(),
	}

	for _, cap := range resp.GetCapabilities() {
		ci := CapabilityInfo{
			Name:        cap.GetName(),
			Description: cap.GetDescription(),
		}
		for _, tool := range cap.GetTools() {
			ci.Tools = append(ci.Tools, ToolInfo{
				Name:                tool.GetName(),
				Description:         tool.GetDescription(),
				ReadOnly:            tool.GetReadOnly(),
				RequiresScanContext: tool.GetRequiresScanContext(),
				Safety:              tool.GetSafety(),
			})
		}
		for _, res := range cap.GetResources() {
			ci.Resources = append(ci.Resources, ResourceInfo{
				URITemplate: res.GetUriTemplate(),
				Name:        res.GetName(),
				Description: res.GetDescription(),
				MimeType:    res.GetMimeType(),
			})
		}
		info.Capabilities = append(info.Capabilities, ci)
	}

	return info
}

// waitForAddr reads from the plugin's stdout looking for a line starting with
// NOX_PLUGIN_ADDR=. It respects the context deadline.
func waitForAddr(ctx context.Context, stdout io.Reader) (string, error) {
	scanner := bufio.NewScanner(stdout)
	addrCh := make(chan string, 1)
	errCh := make(chan error, 1)

	go func() {
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "NOX_PLUGIN_ADDR=") {
				addrCh <- strings.TrimPrefix(line, "NOX_PLUGIN_ADDR=")
				return
			}
		}
		if err := scanner.Err(); err != nil {
			errCh <- err
		} else {
			errCh <- fmt.Errorf("plugin stdout closed without emitting NOX_PLUGIN_ADDR")
		}
	}()

	select {
	case addr := <-addrCh:
		return addr, nil
	case err := <-errCh:
		return "", err
	case <-ctx.Done():
		return "", fmt.Errorf("timed out waiting for plugin address: %w", ctx.Err())
	}
}

// normalizeForStructpb rewrites values structpb rejects into ones it accepts,
// without changing what they mean: []T becomes []any and map[string]T becomes
// map[string]any, recursively.
//
// This exists because the failure it prevents is silent and total.
// structpb.NewStruct converts the whole map or none of it, so one value of an
// unaccepted type does not degrade that value — it fails the InvokeToolRequest,
// and the plugin never runs. The scan then records a diagnostic and reports
// pass. A single `input["exclude"] = []string{...}` in the caller took out 12
// of 20 installed plugins on every workspace that configured scan.exclude,
// including nox/sast and nox/taint-analysis, and the only outward sign was one
// line above a green verdict.
//
// Fixing the caller fixes today. Normalizing here means the next caller that
// writes the obvious Go type cannot reintroduce it. Values structpb genuinely
// cannot represent — a struct, a channel, a non-string-keyed map — are passed
// through untouched and still error, because those are real mistakes and
// should be loud.
func normalizeForStructpb(v any) any {
	switch v.(type) {
	case nil, bool, string, float64, float32,
		int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64,
		[]byte, []any, map[string]any:
		// Already accepted. []byte is deliberate: structpb encodes it as a
		// base64 string, and turning it into []any would change the wire form.
		return v
	}

	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Slice, reflect.Array:
		out := make([]any, rv.Len())
		for i := range out {
			out[i] = normalizeForStructpb(rv.Index(i).Interface())
		}
		return out
	case reflect.Map:
		if rv.Type().Key().Kind() != reflect.String {
			return v // Not representable; let structpb say so.
		}
		out := make(map[string]any, rv.Len())
		for _, k := range rv.MapKeys() {
			out[k.String()] = normalizeForStructpb(rv.MapIndex(k).Interface())
		}
		return out
	default:
		return v
	}
}

// buildInvokeRequest constructs an InvokeToolRequest from the given parameters.
func buildInvokeRequest(toolName string, input map[string]any, workspaceRoot string) (*pluginv1.InvokeToolRequest, error) {
	var inputStruct *structpb.Struct
	if input != nil {
		normalized := make(map[string]any, len(input))
		for k, v := range input {
			normalized[k] = normalizeForStructpb(v)
		}
		var err error
		inputStruct, err = structpb.NewStruct(normalized)
		if err != nil {
			return nil, fmt.Errorf("converting input to structpb: %w", err)
		}
	}
	return &pluginv1.InvokeToolRequest{
		ToolName:      toolName,
		Input:         inputStruct,
		WorkspaceRoot: workspaceRoot,
	}, nil
}
