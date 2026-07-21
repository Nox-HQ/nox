package plugin

import (
	"context"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// The client interceptor must attach the per-launch token to every outgoing
// RPC. A capturing invoker stands in for the real gRPC call.
func TestTokenUnaryInterceptor_AttachesToken(t *testing.T) {
	const token = "cafebabecafebabe"
	var got []string
	invoker := func(ctx context.Context, _ string, _, _ any, _ *grpc.ClientConn, _ ...grpc.CallOption) error {
		md, ok := metadata.FromOutgoingContext(ctx)
		if !ok {
			t.Fatal("no outgoing metadata attached")
		}
		got = md.Get(pluginTokenMetaKey)
		return nil
	}

	err := tokenUnaryInterceptor(token)(context.Background(), "/svc/Method", nil, nil, nil, invoker)
	if err != nil {
		t.Fatalf("interceptor returned error: %v", err)
	}
	if len(got) != 1 || got[0] != token {
		t.Fatalf("attached token = %v, want [%q]", got, token)
	}
}

// Each launch must get a distinct, well-formed 256-bit token; a predictable or
// reused token would let a foreign process forge it.
func TestNewLaunchToken_UniqueAndWellFormed(t *testing.T) {
	seen := make(map[string]bool)
	for range 100 {
		tok, err := newLaunchToken()
		if err != nil {
			t.Fatalf("newLaunchToken: %v", err)
		}
		if len(tok) != 64 {
			t.Fatalf("token length = %d, want 64 hex chars", len(tok))
		}
		if seen[tok] {
			t.Fatalf("duplicate token generated: %q", tok)
		}
		seen[tok] = true
	}
}

// End-to-end: StartBinary spawns a real SDK-based plugin, which enforces the
// token. A successful handshake and tool invocation prove the host passes the
// token via the environment and attaches it on every RPC, and that the SDK
// server accepts exactly that token — the two halves interoperate.
func TestStartBinary_TokenRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a plugin binary; skipped under -short")
	}

	// Windows will not exec a file without an executable extension: the built
	// binary is found but rejected with "executable file not found in %PATH%".
	// go build honours -o verbatim, so the suffix has to be added here.
	bin := filepath.Join(t.TempDir(), "authplugin")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	build := exec.Command("go", "build", "-o", bin, "./testdata/authplugin")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building test plugin: %v\n%s", err, out)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	p, err := StartBinary(ctx, bin, nil, 10*time.Second)
	if err != nil {
		t.Fatalf("StartBinary: %v", err)
	}
	defer func() { _ = p.Close() }()

	if err := p.Handshake(ctx, HostAPIVersion); err != nil {
		t.Fatalf("Handshake through authenticated channel: %v", err)
	}

	resp, err := p.InvokeTool(ctx, "scan", map[string]any{"workspace_root": t.TempDir()}, t.TempDir())
	if err != nil {
		t.Fatalf("InvokeTool through authenticated channel: %v", err)
	}
	if resp == nil {
		t.Fatal("InvokeTool returned nil response")
	}
}

// Guard: the host and SDK must agree on the env var and metadata key, or the
// token would be attached under one name and checked under another — silently
// disabling the control. This pins the wire contract from the host side; the
// SDK side pins the same literals in sdk/auth_test.go.
func TestTokenWireContract(t *testing.T) {
	if pluginTokenEnv != "NOX_PLUGIN_TOKEN" {
		t.Errorf("pluginTokenEnv = %q, want NOX_PLUGIN_TOKEN", pluginTokenEnv)
	}
	if pluginTokenMetaKey != "x-nox-plugin-token" {
		t.Errorf("pluginTokenMetaKey = %q, want x-nox-plugin-token", pluginTokenMetaKey)
	}
	// Metadata keys are case-insensitive but must be lowercase in the map.
	if strings.ToLower(pluginTokenMetaKey) != pluginTokenMetaKey {
		t.Errorf("metadata key must be lowercase: %q", pluginTokenMetaKey)
	}
}
