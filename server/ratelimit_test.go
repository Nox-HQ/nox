package server

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"go.klarlabs.de/mcp"
	"go.klarlabs.de/mcp/protocol"

	"github.com/nox-hq/nox/plugin"
)

// A costly-tier name that does not match a registered tool is a limit that
// silently does not apply. This caught one before it shipped: the plugin runner
// is registered as "plugin.call_tool", and the first draft of costlyTools said
// "plugin_call_tool".
func TestEveryCostlyToolIsARegisteredTool(t *testing.T) {
	s := New("0.1.0", nil, WithPluginHost(plugin.NewHost()))
	srv := mcp.NewServer(mcp.ServerInfo{Name: "nox", Version: "test"})
	s.registerTools(srv)

	registered := map[string]bool{}
	for _, tool := range srv.Tools() {
		registered[tool.Name] = true
	}
	for name := range costlyTools {
		if !registered[name] {
			t.Errorf("costlyTools names %q, which is not a registered tool, so it is never limited", name)
		}
	}
}

func toolCall(name string) *protocol.Request {
	params, _ := json.Marshal(map[string]any{"name": name, "arguments": map[string]any{}})
	return &protocol.Request{JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: "tools/call", Params: params}
}

func chain(t *testing.T) mcp.MiddlewareHandlerFunc {
	t.Helper()
	var h mcp.MiddlewareHandlerFunc = func(context.Context, *protocol.Request) (*protocol.Response, error) {
		return &protocol.Response{JSONRPC: "2.0"}, nil
	}
	mws := rateLimits()
	for i := len(mws) - 1; i >= 0; i-- {
		h = mws[i](h)
	}
	return h
}

func isRateLimited(err error) bool {
	var pe *protocol.Error
	return errors.As(err, &pe) && pe.Code == protocol.CodeRateLimited
}

// A loop of scans is refused once the burst is spent, which is the case the
// limit exists for.
func TestARunawayScanLoopIsRefused(t *testing.T) {
	h := chain(t)
	ctx := context.Background()

	for i := 0; i < costlyBurst; i++ {
		if _, err := h(ctx, toolCall("scan")); err != nil {
			t.Fatalf("scan %d within the burst was refused: %v", i+1, err)
		}
	}
	_, err := h(ctx, toolCall("scan"))
	if !isRateLimited(err) {
		t.Fatalf("expected scan %d to be rate limited, got %v", costlyBurst+1, err)
	}
}

// Triage is cheap and bursty. Spending the scan budget must not stall it, or the
// limit punishes the well-behaved agent it was never aimed at.
func TestTriageIsNotChargedForScans(t *testing.T) {
	h := chain(t)
	ctx := context.Background()

	for i := 0; i < costlyBurst+1; i++ {
		_, _ = h(ctx, toolCall("scan"))
	}
	for i := 0; i < 20; i++ {
		if _, err := h(ctx, toolCall("list_findings")); err != nil {
			t.Fatalf("list_findings %d was refused after the scan budget ran out: %v", i+1, err)
		}
	}
}

// Nothing gets past the ceiling, cheap or not.
func TestEveryRequestHasACeiling(t *testing.T) {
	h := chain(t)
	ctx := context.Background()

	var refused bool
	for i := 0; i < requestBurst+1; i++ {
		if _, err := h(ctx, toolCall("list_findings")); isRateLimited(err) {
			refused = true
			break
		}
	}
	if !refused {
		t.Fatalf("expected the ceiling to refuse within %d requests", requestBurst+1)
	}
}

// A call whose name cannot be read is charged to the tight tier: being
// malformed is not a way round it.
func TestAnUnreadableCallIsChargedAsCostly(t *testing.T) {
	req := &protocol.Request{JSONRPC: "2.0", Method: "tools/call", Params: json.RawMessage(`not json`)}
	if !isCostlyCall(req) {
		t.Fatal("an unreadable tools/call escaped the costly tier")
	}
	if isCostlyCall(&protocol.Request{Method: "tools/list"}) {
		t.Fatal("tools/list was charged as costly")
	}
}
