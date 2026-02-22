package main

import (
	"context"
	"net"
	"testing"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/registry"
	"github.com/nox-hq/nox/sdk"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/structpb"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
)

func TestConformance(t *testing.T) {
	// Inject a fake client so conformance tool invocation doesn't need a real cluster.
	k8sClientFactory = func() (kubernetes.Interface, error) {
		return fake.NewSimpleClientset(), nil
	}
	defer func() { k8sClientFactory = nil }()

	sdk.RunConformance(t, buildServer())
}

func TestTrackConformance(t *testing.T) {
	k8sClientFactory = func() (kubernetes.Interface, error) {
		return fake.NewSimpleClientset(), nil
	}
	defer func() { k8sClientFactory = nil }()

	sdk.RunForTrack(t, buildServer(), registry.TrackDynamicRuntime)
}

func TestHandleScan_WithFakeClient(t *testing.T) {
	// Create a pod that will trigger findings.
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Namespace: "default"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "app",
				Image: "nginx:latest",
			}},
		},
	}

	fakeClient := fake.NewSimpleClientset(pod)
	k8sClientFactory = func() (kubernetes.Interface, error) {
		return fakeClient, nil
	}
	defer func() { k8sClientFactory = nil }()

	client := testPluginClient(t)

	input, err := structpb.NewStruct(map[string]any{
		"namespace": "default",
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.InvokeTool(context.Background(), &pluginv1.InvokeToolRequest{
		ToolName: "scan",
		Input:    input,
	})
	if err != nil {
		t.Fatalf("InvokeTool: %v", err)
	}

	if len(resp.GetFindings()) == 0 {
		t.Error("expected findings from vulnerable pod, got none")
	}

	// Verify at least KRUNT-001 (no security context) and KRUNT-006 (latest).
	rules := make(map[string]bool)
	for _, f := range resp.GetFindings() {
		rules[f.GetRuleId()] = true
	}
	for _, want := range []string{"KRUNT-001", "KRUNT-006"} {
		if !rules[want] {
			t.Errorf("expected %s finding, got rules: %v", want, rules)
		}
	}
}

func TestHandleScan_EmptyCluster(t *testing.T) {
	k8sClientFactory = func() (kubernetes.Interface, error) {
		return fake.NewSimpleClientset(), nil
	}
	defer func() { k8sClientFactory = nil }()

	client := testPluginClient(t)

	input, err := structpb.NewStruct(map[string]any{})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.InvokeTool(context.Background(), &pluginv1.InvokeToolRequest{
		ToolName: "scan",
		Input:    input,
	})
	if err != nil {
		t.Fatalf("InvokeTool: %v", err)
	}

	if len(resp.GetFindings()) != 0 {
		t.Errorf("expected 0 findings for empty cluster, got %d", len(resp.GetFindings()))
	}
}

// testPluginClient creates an in-process gRPC client via bufconn.
func testPluginClient(t *testing.T) pluginv1.PluginServiceClient {
	t.Helper()
	const bufSize = 1024 * 1024

	lis := bufconn.Listen(bufSize)
	grpcServer := grpc.NewServer()
	pluginv1.RegisterPluginServiceServer(grpcServer, buildServer())

	go func() { _ = grpcServer.Serve(lis) }()
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
