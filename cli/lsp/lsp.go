// Package lsp implements a minimal Language Server Protocol (LSP) server for
// nox. It speaks JSON-RPC 2.0 over stdio (with Content-Length framing) and
// publishes nox scan findings as editor diagnostics.
//
// The server is deliberately small and offline: on didOpen/didSave it runs the
// nox scanner against the single opened file and pushes the resulting findings
// back to the editor as textDocument/publishDiagnostics notifications. There is
// no dependency on any third-party LSP library — the JSON-RPC framing is
// hand-rolled on top of encoding/json and bufio.
package lsp

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"

	nox "github.com/nox-hq/nox/core"
	"github.com/nox-hq/nox/core/findings"
)

// ScanFunc scans a single file path and returns the findings for it. It is a
// seam that lets tests drive the server without invoking the real scanner.
type ScanFunc func(path string) ([]findings.Finding, error)

// defaultScan runs the real nox scanner against a single file.
func defaultScan(path string) ([]findings.Finding, error) {
	result, err := nox.RunScan(path)
	if err != nil {
		return nil, err
	}
	// Only active findings become diagnostics: a finding the operator baselined
	// or suppressed was explicitly accepted, and re-surfacing it in the editor
	// contradicts that decision — every other nox surface projects through
	// ActiveFindings, and the editor should not be the one exception.
	return result.Findings.ActiveFindings(), nil
}

// Server is a stdio LSP server instance.
type Server struct {
	reader  *bufio.Reader
	writer  io.Writer
	version string
	scan    ScanFunc
}

// NewServer builds a Server that reads JSON-RPC messages from r and writes
// responses/notifications to w. version is reported back in the initialize
// response's serverInfo.
func NewServer(r io.Reader, w io.Writer, version string) *Server {
	return &Server{
		reader:  bufio.NewReader(r),
		writer:  w,
		version: version,
		scan:    defaultScan,
	}
}

// --- Wire types ---------------------------------------------------------------

// incomingMessage is a decoded JSON-RPC request or notification. Requests carry
// an id; notifications do not.
type incomingMessage struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}

// isRequest reports whether the message expects a response (i.e. it has an id).
func (m *incomingMessage) isRequest() bool {
	return len(m.ID) > 0 && string(m.ID) != "null"
}

type responseMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type notificationMessage struct {
	JSONRPC string      `json:"jsonrpc"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// --- Framing ------------------------------------------------------------------

// writeMessage marshals v to JSON and writes it framed with a Content-Length
// header, per the LSP base protocol.
func writeMessage(w io.Writer, v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "Content-Length: %d\r\n\r\n", len(data)); err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

// readMessage parses one framed message: it reads header lines until the blank
// separator, then reads exactly Content-Length bytes of body. It returns
// io.EOF when the stream is cleanly exhausted before a header.
func readMessage(r *bufio.Reader) ([]byte, error) {
	contentLength := -1
	sawHeader := false
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			if err == io.EOF && !sawHeader && line == "" {
				return nil, io.EOF
			}
			return nil, err
		}
		sawHeader = true
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break // blank line terminates the header block
		}
		if idx := strings.IndexByte(line, ':'); idx >= 0 {
			name := strings.TrimSpace(line[:idx])
			value := strings.TrimSpace(line[idx+1:])
			if strings.EqualFold(name, "Content-Length") {
				n, err := strconv.Atoi(value)
				if err != nil {
					return nil, fmt.Errorf("lsp: invalid Content-Length %q: %w", value, err)
				}
				contentLength = n
			}
		}
	}
	if contentLength < 0 {
		return nil, errors.New("lsp: message missing Content-Length header")
	}
	buf := make([]byte, contentLength)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// --- Serve loop ---------------------------------------------------------------

// Serve runs the read/dispatch loop until an `exit` notification is received or
// the input stream reaches EOF. It returns nil on a clean shutdown.
func (s *Server) Serve() error {
	for {
		body, err := readMessage(s.reader)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		var msg incomingMessage
		if err := json.Unmarshal(body, &msg); err != nil {
			// Malformed frame: skip it rather than tearing down the session.
			continue
		}
		exit, err := s.handle(&msg)
		if err != nil {
			return err
		}
		if exit {
			return nil
		}
	}
}

// handle dispatches a single decoded message. It returns exit=true when the
// serve loop should terminate (on `exit`).
func (s *Server) handle(msg *incomingMessage) (exit bool, err error) {
	switch msg.Method {
	case "initialize":
		return false, s.reply(msg.ID, s.initializeResult())
	case "initialized":
		return false, nil // notification, no-op
	case "textDocument/didOpen", "textDocument/didSave":
		return false, s.scanAndPublish(msg.Params)
	case "textDocument/didClose":
		return false, s.clearDiagnostics(msg.Params)
	case "shutdown":
		// Respond with null result per the LSP spec.
		return false, s.reply(msg.ID, nil)
	case "exit":
		return true, nil
	default:
		if msg.isRequest() {
			return false, s.replyError(msg.ID, -32601, "method not found: "+msg.Method)
		}
		return false, nil // unknown notification: ignore
	}
}

func (s *Server) initializeResult() interface{} {
	return map[string]interface{}{
		"capabilities": map[string]interface{}{
			// 1 == TextDocumentSyncKind.Full
			"textDocumentSync": 1,
		},
		"serverInfo": map[string]interface{}{
			"name":    "nox-lsp",
			"version": s.version,
		},
	}
}

// textDocumentParams captures the { textDocument: { uri } } shape shared by the
// didOpen/didSave/didClose notifications.
type textDocumentParams struct {
	TextDocument struct {
		URI string `json:"uri"`
	} `json:"textDocument"`
}

func parseURI(params json.RawMessage) (string, error) {
	var p textDocumentParams
	if err := json.Unmarshal(params, &p); err != nil {
		return "", err
	}
	if p.TextDocument.URI == "" {
		return "", errors.New("lsp: missing textDocument.uri")
	}
	return p.TextDocument.URI, nil
}

// scanAndPublish resolves the document URI to a path, scans that single file,
// and pushes diagnostics for the URI. On any scan error it publishes an empty
// diagnostics array so a stale set is cleared and the server never crashes.
func (s *Server) scanAndPublish(params json.RawMessage) error {
	uri, err := parseURI(params)
	if err != nil {
		return nil // cannot publish without a URI; ignore quietly
	}
	diags := []Diagnostic{}
	if path, err := uriToPath(uri); err == nil {
		if found, scanErr := s.scan(path); scanErr == nil {
			diags = findingsToDiagnostics(found)
		}
	}
	return s.publishDiagnostics(uri, diags)
}

// clearDiagnostics publishes an empty diagnostics array for a closed document.
func (s *Server) clearDiagnostics(params json.RawMessage) error {
	uri, err := parseURI(params)
	if err != nil {
		return nil
	}
	return s.publishDiagnostics(uri, []Diagnostic{})
}

type publishDiagnosticsParams struct {
	URI         string       `json:"uri"`
	Diagnostics []Diagnostic `json:"diagnostics"`
}

func (s *Server) publishDiagnostics(uri string, diags []Diagnostic) error {
	return writeMessage(s.writer, notificationMessage{
		JSONRPC: "2.0",
		Method:  "textDocument/publishDiagnostics",
		Params: publishDiagnosticsParams{
			URI:         uri,
			Diagnostics: diags,
		},
	})
}

func (s *Server) reply(id json.RawMessage, result interface{}) error {
	data, err := json.Marshal(result)
	if err != nil {
		return err
	}
	return writeMessage(s.writer, responseMessage{
		JSONRPC: "2.0",
		ID:      id,
		Result:  json.RawMessage(data),
	})
}

func (s *Server) replyError(id json.RawMessage, code int, message string) error {
	return writeMessage(s.writer, responseMessage{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &rpcError{Code: code, Message: message},
	})
}

// uriToPath converts a file:// URI to a local filesystem path. Percent-encoding
// is decoded by url.Parse. A leading-slash Windows drive path (/C:/x) is
// normalised to C:/x.
func uriToPath(uri string) (string, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return "", err
	}
	if u.Scheme != "file" {
		return "", fmt.Errorf("lsp: unsupported URI scheme %q", u.Scheme)
	}
	path := u.Path
	if len(path) >= 3 && path[0] == '/' && path[2] == ':' {
		path = path[1:] // strip leading slash before a drive letter
	}
	return filepath.FromSlash(path), nil
}
