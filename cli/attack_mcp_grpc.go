package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"

	"go.klarlabs.de/mcp/protocol"
	pb "go.klarlabs.de/mcp/transport/grpc/mcpv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// grpcClientTransport implements the mcp client's Transport interface over the
// gRPC bidirectional Connect stream.
//
// The mcp library ships a gRPC SERVER transport but no client one — the client
// Transport interface needs Send, and only stdio and HTTP implement it. This
// fills that gap so `nox attack mcp --transport grpc` can capture a manifest
// from a gRPC-hosted MCP server, using the library's own generated protobuf so
// the wire format stays authoritative rather than reinvented.
//
// It mirrors the stdio transport's design: one long-lived stream, a background
// reader that dispatches each response to a per-request channel keyed by
// request id. That is what lets sequential Initialize/ListTools calls share one
// stream without racing.
type grpcClientTransport struct {
	conn   *grpc.ClientConn
	stream grpc.BidiStreamingClient[pb.Message, pb.Message]

	mu       sync.Mutex
	pending  map[string]chan *protocol.Response
	closed   bool
	closeErr error
}

// dialGRPCTransport dials addr and opens the Connect stream. TLS is out of
// scope for V1 capture: an operator points nox at a server they run and have
// isolated, the same trust model as the stdio path, so an insecure local
// channel is the honest default rather than a false sense of transport security.
func dialGRPCTransport(ctx context.Context, addr string) (*grpcClientTransport, error) {
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("dialing gRPC MCP server %s: %w", addr, err)
	}
	stream, err := pb.NewMCPClient(conn).Connect(ctx)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("opening MCP Connect stream: %w", err)
	}
	t := &grpcClientTransport{
		conn:    conn,
		stream:  stream,
		pending: make(map[string]chan *protocol.Response),
	}
	go t.readLoop()
	return t, nil
}

// readLoop reads responses off the stream and hands each to the caller waiting
// on its request id. It ends when the stream closes; a stream error fails every
// in-flight request rather than leaving a caller blocked forever.
func (t *grpcClientTransport) readLoop() {
	for {
		msg, err := t.stream.Recv()
		if err != nil {
			t.failAll(err)
			return
		}
		if msg.GetType() != pb.MessageType_MESSAGE_TYPE_RESPONSE {
			continue
		}
		resp := &protocol.Response{
			JSONRPC: "2.0",
			ID:      json.RawMessage(`"` + msg.GetRequestId() + `"`),
		}
		// Decode the result bytes into a Go value so resp.Result is a
		// map[string]any, matching what the stdio and HTTP transports produce.
		// The mcp client type-asserts resp.Result.(map[string]any); handing it
		// raw bytes would fail that assertion and every capture would error.
		if len(msg.GetResult()) > 0 {
			var result any
			if err := json.Unmarshal(msg.GetResult(), &result); err != nil {
				resp.Error = &protocol.Error{Code: -32603, Message: "decoding result: " + err.Error()}
			} else {
				resp.Result = result
			}
		}
		if e := msg.GetError(); e != nil {
			resp.Error = &protocol.Error{Code: int(e.GetCode()), Message: e.GetMessage()}
		}
		t.deliver(msg.GetRequestId(), resp)
	}
}

// deliver routes a response to its waiting caller.
func (t *grpcClientTransport) deliver(id string, resp *protocol.Response) {
	t.mu.Lock()
	ch := t.pending[id]
	t.mu.Unlock()
	if ch != nil {
		ch <- resp
	}
}

// failAll unblocks every in-flight request when the stream dies.
func (t *grpcClientTransport) failAll(err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closeErr == nil && err != io.EOF {
		t.closeErr = err
	}
	for id, ch := range t.pending {
		close(ch)
		delete(t.pending, id)
	}
}

// Send implements the mcp client Transport interface. A request carries a JSON
// id and waits for the matching response; a notification (no id) is sent
// one-way and returns immediately, matching the JSON-RPC contract the other
// transports honour.
func (t *grpcClientTransport) Send(ctx context.Context, req *protocol.Request) (*protocol.Response, error) {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil, fmt.Errorf("transport closed")
	}
	t.mu.Unlock()

	msg := &pb.Message{
		Method: req.Method,
		Params: []byte(req.Params),
	}

	if req.IsNotification() {
		msg.Type = pb.MessageType_MESSAGE_TYPE_NOTIFICATION
		if err := t.stream.Send(msg); err != nil {
			return nil, fmt.Errorf("sending notification: %w", err)
		}
		return &protocol.Response{JSONRPC: "2.0"}, nil
	}

	id := idString(req.ID)
	msg.Type = pb.MessageType_MESSAGE_TYPE_REQUEST
	msg.RequestId = id

	ch := make(chan *protocol.Response, 1)
	t.mu.Lock()
	t.pending[id] = ch
	t.mu.Unlock()
	defer func() {
		t.mu.Lock()
		delete(t.pending, id)
		t.mu.Unlock()
	}()

	if err := t.stream.Send(msg); err != nil {
		return nil, fmt.Errorf("sending request: %w", err)
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case resp, ok := <-ch:
		if !ok {
			t.mu.Lock()
			err := t.closeErr
			t.mu.Unlock()
			if err == nil {
				err = fmt.Errorf("stream closed before response")
			}
			return nil, err
		}
		return resp, nil
	}
}

// Close closes the stream and connection.
func (t *grpcClientTransport) Close() error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil
	}
	t.closed = true
	t.mu.Unlock()

	_ = t.stream.CloseSend()
	return t.conn.Close()
}

// idString renders a JSON-RPC id as the string the gRPC envelope carries. The
// envelope's request_id is a string, and the mcp client emits numeric ids, so
// the numeric form is stringified and the response id is compared as a string
// on the way back — the pairing stays stable as long as both directions agree,
// which they do because this transport controls both.
func idString(raw json.RawMessage) string {
	s := string(raw)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}
