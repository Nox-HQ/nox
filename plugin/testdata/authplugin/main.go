// Command authplugin is a minimal SDK-based plugin used by the plugin
// package's end-to-end auth test. It exposes a single read-only "scan" tool and
// relies entirely on sdk.Serve for the NOX_PLUGIN_ADDR handshake and the
// per-launch token enforcement, so the test exercises the real host↔SDK path.
package main

import (
	"context"
	"os"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/sdk"
)

func main() {
	manifest := sdk.NewManifest("nox/authtest", "1.0.0").
		Capability("scan", "auth test capability").
		Tool("scan", "no-op scan tool", true).
		Done().
		Build()

	srv := sdk.NewPluginServer(manifest).
		HandleTool("scan", func(_ context.Context, _ sdk.ToolRequest) (*pluginv1.InvokeToolResponse, error) {
			return sdk.NewResponse().Build(), nil
		})

	if err := srv.Serve(context.Background()); err != nil {
		os.Exit(1)
	}
}
