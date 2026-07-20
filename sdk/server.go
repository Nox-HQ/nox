package sdk

import (
	"context"
	"crypto/subtle"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"time"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// pluginTokenEnv is the environment variable through which the host passes a
// per-launch shared secret. When set, every RPC must present the matching token
// or it is rejected — this is what closes the loopback port to callers other
// than the host that spawned this plugin. The key and value must match the
// host's (see plugin.StartBinary).
const pluginTokenEnv = "NOX_PLUGIN_TOKEN"

// pluginTokenMetaKey is the gRPC metadata key carrying the per-launch token.
const pluginTokenMetaKey = "x-nox-plugin-token"

// tokenAuthInterceptor rejects any unary RPC whose metadata does not carry the
// expected per-launch token. Comparison is constant-time. It is only installed
// when the host provided a token, so a plugin run standalone (e.g. by its author
// during development) is unaffected; the real host always sets one.
func tokenAuthInterceptor(token string) grpc.UnaryServerInterceptor {
	want := []byte(token)
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Error(codes.Unauthenticated, "missing plugin auth token")
		}
		vals := md.Get(pluginTokenMetaKey)
		if len(vals) != 1 || subtle.ConstantTimeCompare([]byte(vals[0]), want) != 1 {
			return nil, status.Error(codes.Unauthenticated, "invalid plugin auth token")
		}
		return handler(ctx, req)
	}
}

// PluginServer wraps a gRPC server implementing the PluginService with
// the NOX_PLUGIN_ADDR stdout handshake protocol and signal handling.
type PluginServer struct {
	pluginv1.UnimplementedPluginServiceServer
	manifest *pluginv1.GetManifestResponse
	tools    map[string]ToolHandler
}

// NewPluginServer creates a PluginServer from a pre-built manifest.
func NewPluginServer(manifest *pluginv1.GetManifestResponse) *PluginServer {
	return &PluginServer{
		manifest: manifest,
		tools:    make(map[string]ToolHandler),
	}
}

// HandleTool registers a handler for the named tool. Returns the server for chaining.
func (s *PluginServer) HandleTool(name string, handler ToolHandler) *PluginServer {
	s.tools[name] = handler
	return s
}

// GetManifest implements the PluginService GetManifest RPC.
func (s *PluginServer) GetManifest(_ context.Context, req *pluginv1.GetManifestRequest) (*pluginv1.GetManifestResponse, error) {
	if req.GetApiVersion() != "v1" {
		return nil, status.Errorf(codes.FailedPrecondition, "unsupported API version %q, expected \"v1\"", req.GetApiVersion())
	}
	return s.manifest, nil
}

// InvokeTool implements the PluginService InvokeTool RPC.
func (s *PluginServer) InvokeTool(ctx context.Context, req *pluginv1.InvokeToolRequest) (*pluginv1.InvokeToolResponse, error) {
	handler, ok := s.tools[req.GetToolName()]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "unknown tool %q", req.GetToolName())
	}
	return handler(ctx, RequestFromProto(req))
}

// ServeOption configures the Serve method.
type ServeOption func(*serveConfig)

type serveConfig struct {
	addrWriter io.Writer
}

// WithAddrWriter redirects the NOX_PLUGIN_ADDR output to w instead of os.Stdout.
func WithAddrWriter(w io.Writer) ServeOption {
	return func(cfg *serveConfig) {
		cfg.addrWriter = w
	}
}

// Serve starts the gRPC server, prints the address handshake line, and blocks
// until the context is cancelled or a shutdown signal is received.
func (s *PluginServer) Serve(ctx context.Context, opts ...ServeOption) error {
	cfg := &serveConfig{addrWriter: os.Stdout}
	for _, opt := range opts {
		opt(cfg)
	}

	// Bind loopback-only. A plugin is a subprocess of the host scanner and is
	// only ever dialled over the address handshake below, so exposing it on
	// every interface would let any other local process — or, behind a
	// permissive firewall, any LAN peer — invoke plugin tools during a scan.
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("sdk: listen: %w", err)
	}

	// Require the host's per-launch token on every RPC when one was provided.
	// The host (plugin.StartBinary) always sets it, so in normal operation the
	// loopback port only answers the host that spawned this plugin.
	var serverOpts []grpc.ServerOption
	if token := os.Getenv(pluginTokenEnv); token != "" {
		serverOpts = append(serverOpts, grpc.UnaryInterceptor(tokenAuthInterceptor(token)))
	}

	grpcServer := grpc.NewServer(serverOpts...)
	pluginv1.RegisterPluginServiceServer(grpcServer, s)

	// Print the address for the host to connect to.
	addr := lis.Addr().String()
	_, _ = fmt.Fprintf(cfg.addrWriter, "NOX_PLUGIN_ADDR=%s\n", addr)

	// Serve in a goroutine.
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- grpcServer.Serve(lis)
	}()

	// Wait for context cancellation or shutdown signals.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, shutdownSignals()...)
	defer signal.Stop(sigCh)

	select {
	case <-ctx.Done():
	case <-sigCh:
	case err := <-serveErr:
		return err
	}

	// Graceful shutdown with 5s timeout fallback.
	done := make(chan struct{})
	go func() {
		grpcServer.GracefulStop()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		grpcServer.Stop()
	}

	return nil
}
