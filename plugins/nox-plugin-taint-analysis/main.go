package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/sdk"
)

var version = "dev"

// supportedExtensions maps file extensions to language names.
var supportedExtensions = map[string]string{
	".go": "go",
	".py": "python",
	".js": "javascript",
	".ts": "typescript",
}

// skippedDirs contains directory names to skip during recursive walks.
var skippedDirs = map[string]bool{
	".git":         true,
	"vendor":       true,
	"node_modules": true,
	"__pycache__":  true,
	".venv":        true,
}

// ruleInfo maps rule IDs to severity and description for finding emission.
var ruleInfo = map[string]struct {
	Severity    pluginv1.Severity
	Confidence  pluginv1.Confidence
	Description string
}{
	"TAINT-001": {sdk.SeverityHigh, sdk.ConfidenceHigh, "SQL Injection: tainted input flows to SQL execution"},
	"TAINT-002": {sdk.SeverityCritical, sdk.ConfidenceHigh, "Command Injection: tainted input flows to shell execution"},
	"TAINT-003": {sdk.SeverityHigh, sdk.ConfidenceMedium, "XSS: tainted input flows to HTML output"},
	"TAINT-004": {sdk.SeverityHigh, sdk.ConfidenceHigh, "Path Traversal: tainted input flows to file operations"},
	"TAINT-005": {sdk.SeverityHigh, sdk.ConfidenceMedium, "Code Injection: tainted input flows to eval/deserialization"},
	"TAINT-006": {sdk.SeverityHigh, sdk.ConfidenceHigh, "Cross-function SQL Injection: tainted input flows across function boundaries to SQL execution"},
	"TAINT-007": {sdk.SeverityHigh, sdk.ConfidenceHigh, "Cross-function Command Injection: tainted input flows across function boundaries to shell execution"},
}

func buildServer() *sdk.PluginServer {
	manifest := sdk.NewManifest("nox/taint-analysis", version).
		Capability("taint-analysis", "Intraprocedural taint analysis tracking source-to-sink data flows").
		Tool("scan", "Scan source files for tainted data flows from untrusted input to dangerous sinks", true).
		Done().
		Safety(sdk.WithRiskClass(sdk.RiskPassive)).
		Build()

	return sdk.NewPluginServer(manifest).
		HandleTool("scan", handleScan)
}

func handleScan(ctx context.Context, req sdk.ToolRequest) (*pluginv1.InvokeToolResponse, error) {
	workspaceRoot, _ := req.Input["workspace_root"].(string)
	if workspaceRoot == "" {
		workspaceRoot = req.WorkspaceRoot
	}

	resp := sdk.NewResponse()

	if workspaceRoot == "" {
		return resp.Build(), nil
	}

	// Collect files by directory for interprocedural analysis.
	goFilesByDir := make(map[string]map[string][]byte)
	pyFiles := make(map[string][]byte)
	jsFiles := make(map[string][]byte)

	err := filepath.WalkDir(workspaceRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() {
			if skippedDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		ext := filepath.Ext(path)
		lang, ok := supportedExtensions[ext]
		if !ok {
			return nil
		}

		// Skip Go test files — they typically contain test helpers, not production code.
		if lang == "go" && isGoTestFile(d.Name()) {
			return nil
		}

		// Phase 1: Intraprocedural analysis (existing).
		if scanErr := scanFileForTaint(resp, path, lang); scanErr != nil {
			return nil
		}

		// Phase 2: Collect files for interprocedural analysis.
		content, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}

		switch lang {
		case "go":
			dir := filepath.Dir(path)
			if goFilesByDir[dir] == nil {
				goFilesByDir[dir] = make(map[string][]byte)
			}
			goFilesByDir[dir][path] = content
		case "python":
			pyFiles[path] = content
		case "javascript", "typescript":
			jsFiles[path] = content
		}

		return nil
	})
	if err != nil && err != context.Canceled {
		return nil, fmt.Errorf("walking workspace: %w", err)
	}

	// Phase 2: Interprocedural analysis — Go (per package/directory).
	for _, files := range goFilesByDir {
		if len(files) > 1 {
			interprocFlows := AnalyzeGoFileInterprocedural(files)
			emitInterproceduralFlows(resp, interprocFlows)
		}
	}

	// Phase 2: Interprocedural analysis — Python.
	if len(pyFiles) > 1 {
		interprocFlows := AnalyzeTextFilesInterprocedural(pyFiles, "python")
		emitInterproceduralFlows(resp, interprocFlows)
	}

	// Phase 2: Interprocedural analysis — JS/TS.
	if len(jsFiles) > 1 {
		interprocFlows := AnalyzeTextFilesInterprocedural(jsFiles, "javascript")
		emitInterproceduralFlows(resp, interprocFlows)
	}

	return resp.Build(), nil
}

// emitInterproceduralFlows converts cross-function taint flows to findings.
func emitInterproceduralFlows(resp *sdk.ResponseBuilder, flows []TaintFlow) {
	for i := range flows {
		flow := &flows[i]
		info, ok := ruleInfo[flow.RuleID]
		if !ok {
			continue
		}

		message := fmt.Sprintf("%s: %s flows from %s (line %d) to %s (line %d) via %s",
			info.Description,
			flow.Source.VarName,
			flow.Source.Kind,
			flow.Source.Line,
			flow.SinkExpr,
			flow.SinkLine,
			flow.FuncName,
		)

		resp.Finding(
			flow.RuleID,
			info.Severity,
			info.Confidence,
			message,
		).
			At(flow.FilePath, flow.Source.Line, flow.SinkLine).
			WithMetadata("cwe", flow.CWE).
			WithMetadata("language", flow.Language).
			WithMetadata("source_kind", flow.Source.Kind).
			WithMetadata("source_var", flow.Source.VarName).
			WithMetadata("source_line", fmt.Sprintf("%d", flow.Source.Line)).
			WithMetadata("sink_line", fmt.Sprintf("%d", flow.SinkLine)).
			WithMetadata("function", flow.FuncName).
			WithMetadata("interprocedural", "true").
			WithFingerprint(fingerprint(flow)).
			Done()
	}
}

func scanFileForTaint(resp *sdk.ResponseBuilder, filePath, lang string) error {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil
	}

	var flows []TaintFlow

	switch lang {
	case "go":
		flows = AnalyzeGoFile(filePath, content)
	case "python", "javascript", "typescript":
		flows = AnalyzeTextFile(filePath, content, lang)
	}

	for i := range flows {
		flow := &flows[i]
		info, ok := ruleInfo[flow.RuleID]
		if !ok {
			continue
		}

		message := fmt.Sprintf("%s: %s flows from %s (line %d) to %s (line %d) in %s",
			info.Description,
			flow.Source.VarName,
			flow.Source.Kind,
			flow.Source.Line,
			flow.SinkExpr,
			flow.SinkLine,
			flow.FuncName,
		)

		resp.Finding(
			flow.RuleID,
			info.Severity,
			info.Confidence,
			message,
		).
			At(flow.FilePath, flow.Source.Line, flow.SinkLine).
			WithMetadata("cwe", flow.CWE).
			WithMetadata("language", flow.Language).
			WithMetadata("source_kind", flow.Source.Kind).
			WithMetadata("source_var", flow.Source.VarName).
			WithMetadata("source_line", fmt.Sprintf("%d", flow.Source.Line)).
			WithMetadata("sink_line", fmt.Sprintf("%d", flow.SinkLine)).
			WithMetadata("function", flow.FuncName).
			WithFingerprint(fingerprint(flow)).
			Done()
	}

	return nil
}

func fingerprint(flow *TaintFlow) string {
	return fmt.Sprintf("taint:%s:%s:%s:%d:%d",
		flow.RuleID,
		flow.FilePath,
		flow.FuncName,
		flow.Source.Line,
		flow.SinkLine,
	)
}

func main() {
	os.Exit(run())
}

func run() int {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	srv := buildServer()
	if err := srv.Serve(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "nox-plugin-taint-analysis: %v\n", err)
		return 1
	}
	return 0
}
