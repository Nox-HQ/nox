// Command netplugin is a minimal SDK-based plugin that declares a network
// host, the Go module proxy, the way nox-plugin-freshness does. cli's
// `nox plugin test` tests use it to show a track that allows the host admits
// it and a track that does not refuses it at registration.
package main

import (
	"context"
	"os"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/sdk"
)

func main() {
	manifest := sdk.NewManifest("nox/nettest", "1.0.0").
		Capability("scan", "network test capability").
		Tool("scan", "no-op scan tool", true).
		Done().
		// Declares the Go module proxy, as nox-plugin-freshness does: allowed
		// under the supply-chain track, refused under any track without network.
		Safety(sdk.WithRiskClass(sdk.RiskPassive), sdk.WithNetworkHosts("proxy.golang.org")).
		Build()

	srv := sdk.NewPluginServer(manifest).
		HandleTool("scan", func(_ context.Context, _ sdk.ToolRequest) (*pluginv1.InvokeToolResponse, error) {
			return sdk.NewResponse().Build(), nil
		})

	if err := srv.Serve(context.Background()); err != nil {
		os.Exit(1)
	}
}
