package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/sdk"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

var version = "dev"

// k8sClientFactory allows tests to inject a fake client.
var k8sClientFactory func() (kubernetes.Interface, error)

func buildServer() *sdk.PluginServer {
	manifest := sdk.NewManifest("nox/k8s-runtime", version).
		Capability("k8s-runtime", "Kubernetes runtime security scanning for running workloads").
		Tool("scan", "Inspect running Kubernetes workloads for security misconfigurations", true).
		Done().
		Safety(
			sdk.WithRiskClass(sdk.RiskActive),
			sdk.WithNeedsConfirmation(),
			sdk.WithNetworkHosts("*"),
		).
		Build()

	return sdk.NewPluginServer(manifest).
		HandleTool("scan", handleScan)
}

func handleScan(ctx context.Context, req sdk.ToolRequest) (*pluginv1.InvokeToolResponse, error) {
	namespace := req.InputString("namespace")

	resp := sdk.NewResponse()

	client, err := buildK8sClient()
	if err != nil {
		resp.Diagnostic(pluginv1.DiagnosticSeverity_DIAGNOSTIC_SEVERITY_ERROR,
			fmt.Sprintf("failed to connect to Kubernetes cluster: %v", err),
			"nox/k8s-runtime",
		)
		return resp.Build(), nil
	}

	scanner := NewScanner(client)
	findings, err := scanner.ScanCluster(ctx, namespace)
	if err != nil {
		resp.Diagnostic(pluginv1.DiagnosticSeverity_DIAGNOSTIC_SEVERITY_ERROR,
			fmt.Sprintf("scan failed: %v", err),
			"nox/k8s-runtime",
		)
		return resp.Build(), nil
	}

	for _, f := range findings {
		fb := resp.Finding(f.RuleID, f.Severity, f.Confidence, f.Message).
			At(f.Path, 0, 0).
			WithMetadata("cwe", f.CWE).
			WithMetadata("namespace", f.Namespace).
			WithMetadata("pod", f.Pod)
		if f.Container != "" {
			fb = fb.WithMetadata("container", f.Container)
		}
		for k, v := range f.Metadata {
			fb = fb.WithMetadata(k, v)
		}
		fb.Done()
	}

	return resp.Build(), nil
}

func buildK8sClient() (kubernetes.Interface, error) {
	if k8sClientFactory != nil {
		return k8sClientFactory()
	}

	// Try in-cluster config first.
	config, err := rest.InClusterConfig()
	if err != nil {
		// Fall back to kubeconfig.
		kubeconfigPath := os.Getenv("KUBECONFIG")
		if kubeconfigPath == "" {
			home, _ := os.UserHomeDir()
			kubeconfigPath = filepath.Join(home, ".kube", "config")
		}
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfigPath)
		if err != nil {
			return nil, fmt.Errorf("building k8s config: %w", err)
		}
	}

	return kubernetes.NewForConfig(config)
}

func main() {
	os.Exit(run())
}

func run() int {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	srv := buildServer()
	if err := srv.Serve(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "nox-plugin-k8s-runtime: %v\n", err)
		return 1
	}
	return 0
}
