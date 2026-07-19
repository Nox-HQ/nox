package sdk

import (
	"bytes"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

const bufSize = 1024 * 1024

// newTestClient creates an in-process gRPC client for the given PluginServer using bufconn.
func newTestClient(t *testing.T, srv *PluginServer) pluginv1.PluginServiceClient {
	t.Helper()

	lis := bufconn.Listen(bufSize)
	grpcServer := grpc.NewServer()
	pluginv1.RegisterPluginServiceServer(grpcServer, srv)

	go func() {
		_ = grpcServer.Serve(lis)
	}()
	t.Cleanup(func() { grpcServer.Stop() })

	conn, err := grpc.NewClient(
		"passthrough:///bufconn",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	return pluginv1.NewPluginServiceClient(conn)
}

func TestServer_GetManifest(t *testing.T) {
	manifest := NewManifest("test-plugin", "1.0.0").
		Capability("scan", "Scanning").
		Tool("scan-files", "Scan files", true).
		Done().
		Build()

	srv := NewPluginServer(manifest)
	client := newTestClient(t, srv)

	resp, err := client.GetManifest(context.Background(), &pluginv1.GetManifestRequest{
		ApiVersion: "v1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Name != "test-plugin" {
		t.Errorf("Name = %q, want %q", resp.Name, "test-plugin")
	}
	if resp.Version != "1.0.0" {
		t.Errorf("Version = %q, want %q", resp.Version, "1.0.0")
	}
	if resp.ApiVersion != "v1" {
		t.Errorf("ApiVersion = %q, want %q", resp.ApiVersion, "v1")
	}
	if len(resp.Capabilities) != 1 {
		t.Errorf("expected 1 capability, got %d", len(resp.Capabilities))
	}
}

func TestServer_GetManifest_RejectsWrongVersion(t *testing.T) {
	srv := NewPluginServer(NewManifest("test", "1.0.0").Build())
	client := newTestClient(t, srv)

	_, err := client.GetManifest(context.Background(), &pluginv1.GetManifestRequest{
		ApiVersion: "v999",
	})
	if err == nil {
		t.Fatal("expected error for wrong API version")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %v", err)
	}
	if st.Code() != codes.FailedPrecondition {
		t.Errorf("code = %v, want FailedPrecondition", st.Code())
	}
}

func TestServer_InvokeTool_Dispatch(t *testing.T) {
	manifest := NewManifest("test", "1.0.0").
		Capability("cap", "Cap").
		Tool("echo", "Echo tool", true).
		Done().
		Build()

	srv := NewPluginServer(manifest).
		HandleTool("echo", func(ctx context.Context, req ToolRequest) (*pluginv1.InvokeToolResponse, error) {
			return NewResponse().
				Finding("ECHO-001", SeverityInfo, ConfidenceHigh, "echoed").
				Done().
				Build(), nil
		})

	client := newTestClient(t, srv)

	resp, err := client.InvokeTool(context.Background(), &pluginv1.InvokeToolRequest{
		ToolName:      "echo",
		WorkspaceRoot: "/tmp",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(resp.Findings))
	}
	if resp.Findings[0].RuleId != "ECHO-001" {
		t.Errorf("RuleId = %q", resp.Findings[0].RuleId)
	}
}

func TestServer_InvokeTool_NotFound(t *testing.T) {
	srv := NewPluginServer(NewManifest("test", "1.0.0").Build())
	client := newTestClient(t, srv)

	_, err := client.InvokeTool(context.Background(), &pluginv1.InvokeToolRequest{
		ToolName: "nonexistent",
	})
	if err == nil {
		t.Fatal("expected error for unknown tool")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %v", err)
	}
	if st.Code() != codes.NotFound {
		t.Errorf("code = %v, want NotFound", st.Code())
	}
}

func TestServer_HandleTool_Chainable(t *testing.T) {
	srv := NewPluginServer(NewManifest("test", "1.0.0").Build())
	result := srv.
		HandleTool("a", func(ctx context.Context, req ToolRequest) (*pluginv1.InvokeToolResponse, error) {
			return NewResponse().Build(), nil
		}).
		HandleTool("b", func(ctx context.Context, req ToolRequest) (*pluginv1.InvokeToolResponse, error) {
			return NewResponse().Build(), nil
		})

	if result != srv {
		t.Error("HandleTool should return the same *PluginServer for chaining")
	}
}

func TestServer_InvokeTool_ReceivesCorrectRequest(t *testing.T) {
	manifest := NewManifest("test", "1.0.0").
		Capability("cap", "Cap").
		Tool("check", "Check tool", true).
		Done().
		Build()

	var captured ToolRequest
	srv := NewPluginServer(manifest).
		HandleTool("check", func(ctx context.Context, req ToolRequest) (*pluginv1.InvokeToolResponse, error) {
			captured = req
			return NewResponse().Build(), nil
		})

	client := newTestClient(t, srv)

	_, err := client.InvokeTool(context.Background(), &pluginv1.InvokeToolRequest{
		ToolName:      "check",
		WorkspaceRoot: "/my/workspace",
	})
	if err != nil {
		t.Fatal(err)
	}
	if captured.ToolName != "check" {
		t.Errorf("ToolName = %q, want %q", captured.ToolName, "check")
	}
	if captured.WorkspaceRoot != "/my/workspace" {
		t.Errorf("WorkspaceRoot = %q, want %q", captured.WorkspaceRoot, "/my/workspace")
	}
}

func TestServer_Serve_WritesAddr(t *testing.T) {
	manifest := NewManifest("test", "1.0.0").Build()
	srv := NewPluginServer(manifest)

	var buf bytes.Buffer
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- srv.Serve(ctx, WithAddrWriter(&buf))
	}()

	// Wait briefly for the server to start and write the address.
	// We cancel immediately since we just need to verify the address output.
	cancel()
	<-done

	output := buf.String()
	if !strings.HasPrefix(output, "NOX_PLUGIN_ADDR=") {
		t.Errorf("expected NOX_PLUGIN_ADDR= prefix, got %q", output)
	}
}

// writerFunc adapts a function to io.Writer so a test can observe the
// handshake line the moment Serve emits it, without racing on a Buffer.
type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

// serveAndWaitForAddr starts srv in a goroutine and returns the advertised
// address plus a stop function that cancels and waits for a clean shutdown.
func serveAndWaitForAddr(t *testing.T, srv *PluginServer) (addr string, stop func()) {
	t.Helper()

	addrCh := make(chan string, 1)
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- srv.Serve(ctx, WithAddrWriter(writerFunc(func(p []byte) (int, error) {
			select {
			case addrCh <- string(p):
			default:
			}
			return len(p), nil
		})))
	}()

	stop = func() {
		cancel()
		<-done
	}

	select {
	case line := <-addrCh:
		addr = strings.TrimSpace(strings.TrimPrefix(line, "NOX_PLUGIN_ADDR="))
		return addr, stop
	case <-time.After(5 * time.Second):
		stop()
		t.Fatal("timed out waiting for NOX_PLUGIN_ADDR handshake line")
		return "", stop
	}
}

// A plugin listener reachable from other hosts lets any local process — and,
// depending on firewall posture, any LAN peer — invoke plugin tools mid-scan.
// The listener must be loopback-only.
func TestServer_Serve_BindsLoopbackOnly(t *testing.T) {
	srv := NewPluginServer(NewManifest("test", "1.0.0").Build())

	addr, stop := serveAndWaitForAddr(t, srv)
	defer stop()

	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", addr, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		t.Fatalf("advertised host %q is not an IP literal", host)
	}
	if !ip.IsLoopback() {
		t.Errorf("listener bound to %q, want a loopback address", host)
	}
}

// The loopback bind must not break the handshake contract: the address printed
// on stdout is the only thing the host has to dial, so it must stay connectable.
func TestServer_Serve_AdvertisedAddrIsDialable(t *testing.T) {
	srv := NewPluginServer(NewManifest("test", "1.0.0").Build())

	addr, stop := serveAndWaitForAddr(t, srv)
	defer stop()

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("NewClient(%q): %v", addr, err)
	}
	defer func() { _ = conn.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := pluginv1.NewPluginServiceClient(conn).GetManifest(ctx, &pluginv1.GetManifestRequest{ApiVersion: "v1"})
	if err != nil {
		t.Fatalf("GetManifest over advertised addr %q: %v", addr, err)
	}
	if resp.GetName() != "test" {
		t.Errorf("manifest name = %q, want %q", resp.GetName(), "test")
	}
}
