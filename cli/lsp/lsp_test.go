package lsp

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

// TestFramingRoundTrip verifies that a value written with writeMessage can be
// read back byte-for-byte with readMessage (Content-Length framing).
func TestFramingRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	original := map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "textDocument/didOpen",
		"params":  map[string]interface{}{"n": 42, "s": "héllo, wörld"},
	}
	if err := writeMessage(&buf, original); err != nil {
		t.Fatalf("writeMessage: %v", err)
	}

	// The frame must start with the header and a CRLFCRLF separator.
	if !bytes.Contains(buf.Bytes(), []byte("\r\n\r\n")) {
		t.Fatalf("frame missing CRLFCRLF separator: %q", buf.String())
	}

	r := bufio.NewReader(&buf)
	body, err := readMessage(r)
	if err != nil {
		t.Fatalf("readMessage: %v", err)
	}

	want, _ := json.Marshal(original)
	if !bytes.Equal(body, want) {
		t.Fatalf("round-trip mismatch:\n got %s\nwant %s", body, want)
	}
}

// outMessage is a loosely-typed decode of anything the server writes back.
type outMessage struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Result json.RawMessage `json:"result"`
	Error  *rpcError       `json:"error"`
	Params struct {
		URI         string       `json:"uri"`
		Diagnostics []Diagnostic `json:"diagnostics"`
	} `json:"params"`
}

// drainMessages reads every framed message out of buf until EOF.
func drainMessages(t *testing.T, buf *bytes.Buffer) []outMessage {
	t.Helper()
	r := bufio.NewReader(buf)
	var msgs []outMessage
	for {
		body, err := readMessage(r)
		if err != nil {
			break // EOF or exhausted
		}
		var m outMessage
		if err := json.Unmarshal(body, &m); err != nil {
			t.Fatalf("decode out message %q: %v", body, err)
		}
		msgs = append(msgs, m)
	}
	return msgs
}

// TestServeFullFlow drives initialize -> didOpen -> shutdown -> exit against
// in-memory streams and asserts a publishDiagnostics with a real AI-009
// finding (from `eval(response)` in a temp .py file).
// fileURI builds the file:// URI an LSP client would send for a local path.
//
// It cannot be url.URL{Scheme: "file", Path: p}.String() with a native path: a
// Windows path (C:\dir\f.py) has no leading slash, so String() emits the opaque
// form file:C:%5Cdir%5Cf.py. url.Parse then leaves Path empty, uriToPath
// resolves nothing, and the scan silently returns zero diagnostics — which
// looked like the LSP was broken on Windows when it is only this construction
// that was. Real clients send file:///C:/dir/f.py, which uriToPath already
// handles; producing that same form keeps the test honest about what ships.
func fileURI(p string) string {
	slashed := filepath.ToSlash(p)
	if !strings.HasPrefix(slashed, "/") {
		slashed = "/" + slashed // drive-letter paths need the LSP leading slash
	}
	return (&url.URL{Scheme: "file", Path: slashed}).String()
}

func TestServeFullFlow(t *testing.T) {
	dir := t.TempDir()
	pyPath := filepath.Join(dir, "vuln.py")
	src := "import x\nresponse = get()\ndata = eval(response)\n"
	if err := os.WriteFile(pyPath, []byte(src), 0o644); err != nil {
		t.Fatalf("write temp py: %v", err)
	}
	uri := fileURI(pyPath)

	var in bytes.Buffer
	mustWrite(t, &in, map[string]interface{}{
		"jsonrpc": "2.0", "id": 1, "method": "initialize",
		"params": map[string]interface{}{},
	})
	mustWrite(t, &in, map[string]interface{}{
		"jsonrpc": "2.0", "method": "textDocument/didOpen",
		"params": map[string]interface{}{
			"textDocument": map[string]interface{}{"uri": uri, "text": src},
		},
	})
	mustWrite(t, &in, map[string]interface{}{
		"jsonrpc": "2.0", "id": 2, "method": "shutdown",
	})
	mustWrite(t, &in, map[string]interface{}{
		"jsonrpc": "2.0", "method": "exit",
	})

	var out bytes.Buffer
	srv := NewServer(&in, &out, "test")
	if err := srv.Serve(); err != nil {
		t.Fatalf("Serve returned error: %v", err)
	}

	msgs := drainMessages(t, &out)

	// initialize response must advertise Full sync and serverInfo.
	init := findByID(t, msgs, "1")
	var initResult struct {
		Capabilities struct {
			TextDocumentSync int `json:"textDocumentSync"`
		} `json:"capabilities"`
		ServerInfo struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"serverInfo"`
	}
	if err := json.Unmarshal(init.Result, &initResult); err != nil {
		t.Fatalf("decode initialize result: %v", err)
	}
	if initResult.Capabilities.TextDocumentSync != 1 {
		t.Errorf("textDocumentSync = %d, want 1 (Full)", initResult.Capabilities.TextDocumentSync)
	}
	if initResult.ServerInfo.Name == "" || initResult.ServerInfo.Version != "test" {
		t.Errorf("unexpected serverInfo: %+v", initResult.ServerInfo)
	}

	// publishDiagnostics for the URI with an AI-009 error diagnostic.
	var pub *outMessage
	for i := range msgs {
		if msgs[i].Method == "textDocument/publishDiagnostics" {
			pub = &msgs[i]
			break
		}
	}
	if pub == nil {
		t.Fatalf("no publishDiagnostics notification; got %d messages", len(msgs))
	}
	if pub.Params.URI != uri {
		t.Errorf("publishDiagnostics uri = %q, want %q", pub.Params.URI, uri)
	}
	if len(pub.Params.Diagnostics) < 1 {
		t.Fatalf("expected >=1 diagnostic, got %d", len(pub.Params.Diagnostics))
	}
	var found *Diagnostic
	for i := range pub.Params.Diagnostics {
		if pub.Params.Diagnostics[i].Code == "AI-009" {
			found = &pub.Params.Diagnostics[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("no AI-009 diagnostic in %+v", pub.Params.Diagnostics)
	}
	if found.Severity != severityError {
		t.Errorf("AI-009 severity = %d, want %d (Error)", found.Severity, severityError)
	}
	if found.Source != "nox" {
		t.Errorf("diagnostic source = %q, want nox", found.Source)
	}
	// eval(response) is on the 3rd line (0-based line 2).
	if found.Range.Start.Line != 2 {
		t.Errorf("AI-009 start line = %d, want 2", found.Range.Start.Line)
	}

	// shutdown response must be a JSON null result.
	sh := findByID(t, msgs, "2")
	if string(sh.Result) != "null" {
		t.Errorf("shutdown result = %q, want null", sh.Result)
	}
}

// TestShutdownExitReturns confirms the serve loop returns cleanly on exit and
// that shutdown yields a null result.
func TestShutdownExitReturns(t *testing.T) {
	var in bytes.Buffer
	mustWrite(t, &in, map[string]interface{}{"jsonrpc": "2.0", "id": 7, "method": "shutdown"})
	mustWrite(t, &in, map[string]interface{}{"jsonrpc": "2.0", "method": "exit"})

	var out bytes.Buffer
	srv := NewServer(&in, &out, "test")
	if err := srv.Serve(); err != nil {
		t.Fatalf("Serve should return nil on exit, got %v", err)
	}

	msgs := drainMessages(t, &out)
	if len(msgs) != 1 {
		t.Fatalf("expected exactly 1 response (shutdown), got %d", len(msgs))
	}
	if string(msgs[0].Result) != "null" {
		t.Errorf("shutdown result = %q, want null", msgs[0].Result)
	}
}

// TestUnknownRequestError verifies an unknown request gets a -32601 error and
// an unknown notification is silently ignored.
func TestUnknownRequestError(t *testing.T) {
	var in bytes.Buffer
	mustWrite(t, &in, map[string]interface{}{"jsonrpc": "2.0", "method": "$/setTrace"}) // notification: ignored
	mustWrite(t, &in, map[string]interface{}{"jsonrpc": "2.0", "id": 9, "method": "totally/unknown"})
	mustWrite(t, &in, map[string]interface{}{"jsonrpc": "2.0", "method": "exit"})

	var out bytes.Buffer
	if err := NewServer(&in, &out, "test").Serve(); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	msgs := drainMessages(t, &out)
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message (error for the request only), got %d", len(msgs))
	}
	if msgs[0].Error == nil || msgs[0].Error.Code != -32601 {
		t.Fatalf("expected -32601 error, got %+v", msgs[0].Error)
	}
}

// TestDidCloseClearsDiagnostics verifies didClose publishes an empty array.
func TestDidCloseClearsDiagnostics(t *testing.T) {
	uri := "file:///tmp/whatever.py"
	var in bytes.Buffer
	mustWrite(t, &in, map[string]interface{}{
		"jsonrpc": "2.0", "method": "textDocument/didClose",
		"params": map[string]interface{}{
			"textDocument": map[string]interface{}{"uri": uri},
		},
	})
	mustWrite(t, &in, map[string]interface{}{"jsonrpc": "2.0", "method": "exit"})

	var out bytes.Buffer
	if err := NewServer(&in, &out, "test").Serve(); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	msgs := drainMessages(t, &out)
	if len(msgs) != 1 || msgs[0].Method != "textDocument/publishDiagnostics" {
		t.Fatalf("expected 1 publishDiagnostics, got %+v", msgs)
	}
	if msgs[0].Params.URI != uri {
		t.Errorf("uri = %q, want %q", msgs[0].Params.URI, uri)
	}
	if len(msgs[0].Params.Diagnostics) != 0 {
		t.Errorf("expected empty diagnostics, got %d", len(msgs[0].Params.Diagnostics))
	}
}

// TestScanErrorPublishesEmpty verifies a failing scan yields an empty
// diagnostics array rather than crashing the loop.
func TestScanErrorPublishesEmpty(t *testing.T) {
	var in bytes.Buffer
	mustWrite(t, &in, map[string]interface{}{
		"jsonrpc": "2.0", "method": "textDocument/didSave",
		"params": map[string]interface{}{
			"textDocument": map[string]interface{}{"uri": "file:///tmp/x.py"},
		},
	})
	mustWrite(t, &in, map[string]interface{}{"jsonrpc": "2.0", "method": "exit"})

	var out bytes.Buffer
	srv := NewServer(&in, &out, "test")
	srv.scan = func(string) ([]findings.Finding, error) {
		return nil, os.ErrNotExist // simulate a scan failure
	}
	if err := srv.Serve(); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	msgs := drainMessages(t, &out)
	if len(msgs) != 1 || len(msgs[0].Params.Diagnostics) != 0 {
		t.Fatalf("expected 1 message with empty diagnostics, got %+v", msgs)
	}
}

func mustWrite(t *testing.T, w *bytes.Buffer, v interface{}) {
	t.Helper()
	if err := writeMessage(w, v); err != nil {
		t.Fatalf("writeMessage: %v", err)
	}
}

func findByID(t *testing.T, msgs []outMessage, id string) outMessage {
	t.Helper()
	for _, m := range msgs {
		if string(m.ID) == id {
			return m
		}
	}
	t.Fatalf("no response with id=%s among %d messages", id, len(msgs))
	return outMessage{}
}
