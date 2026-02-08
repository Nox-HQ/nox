package plugin

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
	"time"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/structpb"
)

// HostAPIVersion is the protocol version the host advertises during handshake.
const HostAPIVersion = "v1"

// PluginState represents the lifecycle state of a plugin connection.
type PluginState int

const (
	StateInit     PluginState = iota // Created, not yet handshaken.
	StateReady                       // Handshake complete, ready for tool invocations.
	StateStopping                    // Shutdown in progress.
	StateStopped                     // Cleanly shut down.
	StateFailed                      // Failed during handshake or runtime.
)

// Diagnostic is a non-finding message emitted by a plugin.
type Diagnostic struct {
	Severity string
	Message  string
	Source   string
}

// PluginInfo holds the parsed manifest from a plugin after handshake.
type PluginInfo struct {
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
	Name        string
	Description string
	ReadOnly    bool
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
	info        PluginInfo
	state       PluginState
	client      pluginv1.PluginServiceClient
	conn        *grpc.ClientConn
	cmd         *exec.Cmd // nil if connected to an external process
	rateLimiter *RateLimiter
	mu          sync.Mutex
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
	cmd := exec.CommandContext(ctx, path, args...)
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

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
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
func (p *Plugin) Info() PluginInfo {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.info
}

// State returns the current plugin lifecycle state.
func (p *Plugin) State() PluginState {
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

// parseManifest extracts a PluginInfo from a GetManifestResponse.
func parseManifest(resp *pluginv1.GetManifestResponse) PluginInfo {
	info := PluginInfo{
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
				Name:        tool.GetName(),
				Description: tool.GetDescription(),
				ReadOnly:    tool.GetReadOnly(),
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

// buildInvokeRequest constructs an InvokeToolRequest from the given parameters.
func buildInvokeRequest(toolName string, input map[string]any, workspaceRoot string) (*pluginv1.InvokeToolRequest, error) {
	var inputStruct *structpb.Struct
	if input != nil {
		var err error
		inputStruct, err = structpb.NewStruct(input)
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
