package sdk

import (
	"context"
	"testing"
	"time"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// dialGetManifest connects to addr over an insecure loopback channel and calls
// GetManifest, optionally attaching outgoing metadata. It models exactly what a
// foreign local process could do: reach the plugin's port and try to drive it.
func dialGetManifest(t *testing.T, addr string, md metadata.MD) error {
	t.Helper()
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	defer func() { _ = conn.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if md != nil {
		ctx = metadata.NewOutgoingContext(ctx, md)
	}
	_, err = pluginv1.NewPluginServiceClient(conn).GetManifest(ctx, &pluginv1.GetManifestRequest{ApiVersion: "v1"})
	return err
}

// When the host sets NOX_PLUGIN_TOKEN, the plugin's gRPC server must accept only
// callers presenting the matching token and reject everyone else. This is the
// control that closes the unauthenticated loopback port to any other local
// process (or LAN peer) for the lifetime of a scan.
func TestServe_TokenAuth_RejectsUnauthenticatedCallers(t *testing.T) {
	const token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	t.Setenv(pluginTokenEnv, token)

	srv := NewPluginServer(NewManifest("test", "1.0.0").Build())
	addr, stop := serveAndWaitForAddr(t, srv)
	defer stop()

	// No token — the foreign-process case — is rejected.
	if err := dialGetManifest(t, addr, nil); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("no-token call: got code %v (%v), want Unauthenticated", status.Code(err), err)
	}

	// A guessed/wrong token is rejected.
	wrong := metadata.Pairs(pluginTokenMetaKey, "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
	if err := dialGetManifest(t, addr, wrong); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("wrong-token call: got code %v (%v), want Unauthenticated", status.Code(err), err)
	}

	// The correct token — what the host attaches — is accepted.
	right := metadata.Pairs(pluginTokenMetaKey, token)
	if err := dialGetManifest(t, addr, right); err != nil {
		t.Fatalf("correct-token call: got %v, want success", err)
	}
}

// A plugin started without a token in its environment (standalone during
// development, or by a host predating this control) keeps its prior behavior and
// does not require authentication — so the change is backward compatible.
func TestServe_NoToken_NoEnforcement(t *testing.T) {
	// Empty value ⇒ Serve installs no interceptor, matching an unset variable.
	t.Setenv(pluginTokenEnv, "")

	srv := NewPluginServer(NewManifest("test", "1.0.0").Build())
	addr, stop := serveAndWaitForAddr(t, srv)
	defer stop()

	if err := dialGetManifest(t, addr, nil); err != nil {
		t.Fatalf("no-token-env call: got %v, want success (no enforcement)", err)
	}
}
