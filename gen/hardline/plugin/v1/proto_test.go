package pluginv1_test

import (
	"testing"

	pluginv1 "github.com/felixgeelhaar/hardline/gen/hardline/plugin/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

// roundTrip marshals and unmarshals a proto message, returning a fresh copy.
func roundTrip[T proto.Message](t *testing.T, msg T) T {
	t.Helper()
	data, err := proto.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	out := msg.ProtoReflect().New().Interface().(T)
	if err := proto.Unmarshal(data, out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return out
}

func TestFindingRoundTrip(t *testing.T) {
	original := &pluginv1.Finding{
		Id:         "f-001",
		RuleId:     "SEC-001",
		Severity:   pluginv1.Severity_SEVERITY_HIGH,
		Confidence: pluginv1.Confidence_CONFIDENCE_MEDIUM,
		Location: &pluginv1.Location{
			FilePath:    "src/main.go",
			StartLine:   42,
			EndLine:     42,
			StartColumn: 10,
			EndColumn:   25,
		},
		Message:     "Hardcoded secret detected",
		Fingerprint: "abc123",
		Metadata: map[string]string{
			"category": "secrets",
			"source":   "pattern-match",
		},
	}

	got := roundTrip(t, original)

	if got.GetId() != "f-001" {
		t.Errorf("id: got %q, want %q", got.GetId(), "f-001")
	}
	if got.GetRuleId() != "SEC-001" {
		t.Errorf("rule_id: got %q, want %q", got.GetRuleId(), "SEC-001")
	}
	if got.GetSeverity() != pluginv1.Severity_SEVERITY_HIGH {
		t.Errorf("severity: got %v, want SEVERITY_HIGH", got.GetSeverity())
	}
	if got.GetConfidence() != pluginv1.Confidence_CONFIDENCE_MEDIUM {
		t.Errorf("confidence: got %v, want CONFIDENCE_MEDIUM", got.GetConfidence())
	}
	if got.GetLocation().GetFilePath() != "src/main.go" {
		t.Errorf("location.file_path: got %q, want %q", got.GetLocation().GetFilePath(), "src/main.go")
	}
	if got.GetLocation().GetStartLine() != 42 {
		t.Errorf("location.start_line: got %d, want 42", got.GetLocation().GetStartLine())
	}
	if got.GetMessage() != "Hardcoded secret detected" {
		t.Errorf("message: got %q, want %q", got.GetMessage(), "Hardcoded secret detected")
	}
	if got.GetFingerprint() != "abc123" {
		t.Errorf("fingerprint: got %q, want %q", got.GetFingerprint(), "abc123")
	}
	if v, ok := got.GetMetadata()["category"]; !ok || v != "secrets" {
		t.Errorf("metadata[category]: got %q, want %q", v, "secrets")
	}
}

func TestArtifactRoundTrip(t *testing.T) {
	original := &pluginv1.Artifact{
		Path:     "configs/app.yaml",
		AbsPath:  "/home/user/project/configs/app.yaml",
		Type:     pluginv1.ArtifactType_ARTIFACT_TYPE_CONFIG,
		Size:     1024,
		Content:  []byte("key: value\n"),
		MimeType: "text/yaml",
	}

	got := roundTrip(t, original)

	if got.GetPath() != "configs/app.yaml" {
		t.Errorf("path: got %q, want %q", got.GetPath(), "configs/app.yaml")
	}
	if got.GetAbsPath() != "/home/user/project/configs/app.yaml" {
		t.Errorf("abs_path: got %q, want %q", got.GetAbsPath(), "/home/user/project/configs/app.yaml")
	}
	if got.GetType() != pluginv1.ArtifactType_ARTIFACT_TYPE_CONFIG {
		t.Errorf("type: got %v, want ARTIFACT_TYPE_CONFIG", got.GetType())
	}
	if got.GetSize() != 1024 {
		t.Errorf("size: got %d, want 1024", got.GetSize())
	}
	if string(got.GetContent()) != "key: value\n" {
		t.Errorf("content: got %q, want %q", string(got.GetContent()), "key: value\n")
	}
	if got.GetMimeType() != "text/yaml" {
		t.Errorf("mime_type: got %q, want %q", got.GetMimeType(), "text/yaml")
	}
}

func TestPackageRoundTrip(t *testing.T) {
	original := &pluginv1.Package{
		Name:      "lodash",
		Version:   "4.17.21",
		Ecosystem: "npm",
	}

	got := roundTrip(t, original)

	if got.GetName() != "lodash" {
		t.Errorf("name: got %q, want %q", got.GetName(), "lodash")
	}
	if got.GetVersion() != "4.17.21" {
		t.Errorf("version: got %q, want %q", got.GetVersion(), "4.17.21")
	}
	if got.GetEcosystem() != "npm" {
		t.Errorf("ecosystem: got %q, want %q", got.GetEcosystem(), "npm")
	}
}

func TestAIComponentRoundTrip(t *testing.T) {
	original := &pluginv1.AIComponent{
		Name: "chat-agent",
		Type: "agent",
		Path: "agents/chat.yaml",
		Details: map[string]string{
			"model":    "gpt-4",
			"provider": "openai",
		},
	}

	got := roundTrip(t, original)

	if got.GetName() != "chat-agent" {
		t.Errorf("name: got %q, want %q", got.GetName(), "chat-agent")
	}
	if got.GetType() != "agent" {
		t.Errorf("type: got %q, want %q", got.GetType(), "agent")
	}
	if got.GetPath() != "agents/chat.yaml" {
		t.Errorf("path: got %q, want %q", got.GetPath(), "agents/chat.yaml")
	}
	if v, ok := got.GetDetails()["model"]; !ok || v != "gpt-4" {
		t.Errorf("details[model]: got %q, want %q", v, "gpt-4")
	}
}

func TestGetManifestResponseRoundTrip(t *testing.T) {
	schema, err := structpb.NewStruct(map[string]any{
		"type": "object",
		"properties": map[string]any{
			"target": map[string]any{
				"type": "string",
			},
		},
	})
	if err != nil {
		t.Fatalf("create struct: %v", err)
	}

	original := &pluginv1.GetManifestResponse{
		Name:       "dast-scanner",
		Version:    "1.0.0",
		ApiVersion: "v1",
		Capabilities: []*pluginv1.Capability{
			{
				Name:        "dast.scan",
				Description: "Dynamic application security testing",
				Tools: []*pluginv1.ToolDef{
					{
						Name:        "scan",
						Description: "Run a DAST scan against a target URL",
						InputSchema: schema,
						ReadOnly:    true,
					},
				},
				Resources: []*pluginv1.ResourceDef{
					{
						UriTemplate: "dast://runs/{id}/results.sarif",
						Name:        "SARIF results",
						Description: "Scan results in SARIF format",
						MimeType:    "application/sarif+json",
					},
				},
			},
		},
		Safety: &pluginv1.SafetyRequirements{
			NetworkHosts:     []string{"*.example.com"},
			NetworkCidrs:     []string{"10.0.0.0/8"},
			FilePaths:        []string{"/tmp/dast-output"},
			EnvVars:          []string{"DAST_API_KEY"},
			RiskClass:        "active",
			NeedsConfirmation: true,
			MaxArtifactBytes: 10 * 1024 * 1024,
		},
	}

	got := roundTrip(t, original)

	if got.GetName() != "dast-scanner" {
		t.Errorf("name: got %q, want %q", got.GetName(), "dast-scanner")
	}
	if got.GetVersion() != "1.0.0" {
		t.Errorf("version: got %q, want %q", got.GetVersion(), "1.0.0")
	}
	if got.GetApiVersion() != "v1" {
		t.Errorf("api_version: got %q, want %q", got.GetApiVersion(), "v1")
	}
	if len(got.GetCapabilities()) != 1 {
		t.Fatalf("capabilities: got %d, want 1", len(got.GetCapabilities()))
	}
	cap := got.GetCapabilities()[0]
	if cap.GetName() != "dast.scan" {
		t.Errorf("capability.name: got %q, want %q", cap.GetName(), "dast.scan")
	}
	if len(cap.GetTools()) != 1 {
		t.Fatalf("tools: got %d, want 1", len(cap.GetTools()))
	}
	tool := cap.GetTools()[0]
	if tool.GetName() != "scan" {
		t.Errorf("tool.name: got %q, want %q", tool.GetName(), "scan")
	}
	if !tool.GetReadOnly() {
		t.Error("tool.read_only: got false, want true")
	}
	if tool.GetInputSchema() == nil {
		t.Fatal("tool.input_schema: got nil")
	}
	if len(cap.GetResources()) != 1 {
		t.Fatalf("resources: got %d, want 1", len(cap.GetResources()))
	}
	res := cap.GetResources()[0]
	if res.GetUriTemplate() != "dast://runs/{id}/results.sarif" {
		t.Errorf("resource.uri_template: got %q", res.GetUriTemplate())
	}

	safety := got.GetSafety()
	if safety == nil {
		t.Fatal("safety: got nil")
	}
	if safety.GetRiskClass() != "active" {
		t.Errorf("safety.risk_class: got %q, want %q", safety.GetRiskClass(), "active")
	}
	if !safety.GetNeedsConfirmation() {
		t.Error("safety.needs_confirmation: got false, want true")
	}
	if safety.GetMaxArtifactBytes() != 10*1024*1024 {
		t.Errorf("safety.max_artifact_bytes: got %d, want %d", safety.GetMaxArtifactBytes(), 10*1024*1024)
	}
}

func TestInvokeToolRoundTrip(t *testing.T) {
	input, err := structpb.NewStruct(map[string]any{
		"target": "https://example.com",
		"depth":  float64(3),
	})
	if err != nil {
		t.Fatalf("create struct: %v", err)
	}

	req := &pluginv1.InvokeToolRequest{
		ToolName:      "scan",
		Input:         input,
		WorkspaceRoot: "/home/user/project",
	}

	gotReq := roundTrip(t, req)
	if gotReq.GetToolName() != "scan" {
		t.Errorf("tool_name: got %q, want %q", gotReq.GetToolName(), "scan")
	}
	if gotReq.GetInput().GetFields()["target"].GetStringValue() != "https://example.com" {
		t.Errorf("input.target: got %q", gotReq.GetInput().GetFields()["target"].GetStringValue())
	}
	if gotReq.GetWorkspaceRoot() != "/home/user/project" {
		t.Errorf("workspace_root: got %q", gotReq.GetWorkspaceRoot())
	}

	resp := &pluginv1.InvokeToolResponse{
		Findings: []*pluginv1.Finding{
			{
				Id:       "f-001",
				RuleId:   "XSS-001",
				Severity: pluginv1.Severity_SEVERITY_HIGH,
				Message:  "Reflected XSS found",
			},
		},
		Packages: []*pluginv1.Package{
			{Name: "express", Version: "4.18.2", Ecosystem: "npm"},
		},
		AiComponents: []*pluginv1.AIComponent{
			{Name: "rag-pipeline", Type: "prompt", Path: "prompts/rag.txt"},
		},
		Diagnostics: []*pluginv1.Diagnostic{
			{
				Severity: pluginv1.DiagnosticSeverity_DIAGNOSTIC_SEVERITY_WARNING,
				Message:  "Rate limit approaching",
				Source:   "dast-scanner",
			},
		},
	}

	gotResp := roundTrip(t, resp)
	if len(gotResp.GetFindings()) != 1 {
		t.Fatalf("findings: got %d, want 1", len(gotResp.GetFindings()))
	}
	if gotResp.GetFindings()[0].GetSeverity() != pluginv1.Severity_SEVERITY_HIGH {
		t.Errorf("finding.severity: got %v", gotResp.GetFindings()[0].GetSeverity())
	}
	if len(gotResp.GetPackages()) != 1 {
		t.Fatalf("packages: got %d, want 1", len(gotResp.GetPackages()))
	}
	if len(gotResp.GetAiComponents()) != 1 {
		t.Fatalf("ai_components: got %d, want 1", len(gotResp.GetAiComponents()))
	}
	if len(gotResp.GetDiagnostics()) != 1 {
		t.Fatalf("diagnostics: got %d, want 1", len(gotResp.GetDiagnostics()))
	}
	if gotResp.GetDiagnostics()[0].GetSeverity() != pluginv1.DiagnosticSeverity_DIAGNOSTIC_SEVERITY_WARNING {
		t.Errorf("diagnostic.severity: got %v", gotResp.GetDiagnostics()[0].GetSeverity())
	}
}

func TestStreamArtifactsRoundTrip(t *testing.T) {
	req := &pluginv1.StreamArtifactsRequest{
		RunId: "run-abc-123",
		ArtifactTypes: []pluginv1.ArtifactType{
			pluginv1.ArtifactType_ARTIFACT_TYPE_SOURCE,
			pluginv1.ArtifactType_ARTIFACT_TYPE_CONFIG,
		},
	}

	gotReq := roundTrip(t, req)
	if gotReq.GetRunId() != "run-abc-123" {
		t.Errorf("run_id: got %q, want %q", gotReq.GetRunId(), "run-abc-123")
	}
	if len(gotReq.GetArtifactTypes()) != 2 {
		t.Fatalf("artifact_types: got %d, want 2", len(gotReq.GetArtifactTypes()))
	}
	if gotReq.GetArtifactTypes()[0] != pluginv1.ArtifactType_ARTIFACT_TYPE_SOURCE {
		t.Errorf("artifact_types[0]: got %v", gotReq.GetArtifactTypes()[0])
	}

	resp := &pluginv1.StreamArtifactsResponse{
		Artifact: &pluginv1.Artifact{
			Path: "src/main.go",
			Type: pluginv1.ArtifactType_ARTIFACT_TYPE_SOURCE,
			Size: 512,
		},
	}

	gotResp := roundTrip(t, resp)
	if gotResp.GetArtifact().GetPath() != "src/main.go" {
		t.Errorf("artifact.path: got %q", gotResp.GetArtifact().GetPath())
	}
}

func TestEnumValues(t *testing.T) {
	tests := []struct {
		name  string
		enum  int32
		str   string
	}{
		{"SEVERITY_UNSPECIFIED", int32(pluginv1.Severity_SEVERITY_UNSPECIFIED), "SEVERITY_UNSPECIFIED"},
		{"SEVERITY_CRITICAL", int32(pluginv1.Severity_SEVERITY_CRITICAL), "SEVERITY_CRITICAL"},
		{"SEVERITY_HIGH", int32(pluginv1.Severity_SEVERITY_HIGH), "SEVERITY_HIGH"},
		{"SEVERITY_MEDIUM", int32(pluginv1.Severity_SEVERITY_MEDIUM), "SEVERITY_MEDIUM"},
		{"SEVERITY_LOW", int32(pluginv1.Severity_SEVERITY_LOW), "SEVERITY_LOW"},
		{"SEVERITY_INFO", int32(pluginv1.Severity_SEVERITY_INFO), "SEVERITY_INFO"},
		{"CONFIDENCE_UNSPECIFIED", int32(pluginv1.Confidence_CONFIDENCE_UNSPECIFIED), "CONFIDENCE_UNSPECIFIED"},
		{"CONFIDENCE_HIGH", int32(pluginv1.Confidence_CONFIDENCE_HIGH), "CONFIDENCE_HIGH"},
		{"CONFIDENCE_MEDIUM", int32(pluginv1.Confidence_CONFIDENCE_MEDIUM), "CONFIDENCE_MEDIUM"},
		{"CONFIDENCE_LOW", int32(pluginv1.Confidence_CONFIDENCE_LOW), "CONFIDENCE_LOW"},
		{"ARTIFACT_TYPE_UNSPECIFIED", int32(pluginv1.ArtifactType_ARTIFACT_TYPE_UNSPECIFIED), "ARTIFACT_TYPE_UNSPECIFIED"},
		{"ARTIFACT_TYPE_SOURCE", int32(pluginv1.ArtifactType_ARTIFACT_TYPE_SOURCE), "ARTIFACT_TYPE_SOURCE"},
		{"ARTIFACT_TYPE_CONFIG", int32(pluginv1.ArtifactType_ARTIFACT_TYPE_CONFIG), "ARTIFACT_TYPE_CONFIG"},
		{"ARTIFACT_TYPE_LOCKFILE", int32(pluginv1.ArtifactType_ARTIFACT_TYPE_LOCKFILE), "ARTIFACT_TYPE_LOCKFILE"},
		{"ARTIFACT_TYPE_CONTAINER", int32(pluginv1.ArtifactType_ARTIFACT_TYPE_CONTAINER), "ARTIFACT_TYPE_CONTAINER"},
		{"ARTIFACT_TYPE_AI_COMPONENT", int32(pluginv1.ArtifactType_ARTIFACT_TYPE_AI_COMPONENT), "ARTIFACT_TYPE_AI_COMPONENT"},
		{"ARTIFACT_TYPE_UNKNOWN", int32(pluginv1.ArtifactType_ARTIFACT_TYPE_UNKNOWN), "ARTIFACT_TYPE_UNKNOWN"},
		{"DIAGNOSTIC_SEVERITY_UNSPECIFIED", int32(pluginv1.DiagnosticSeverity_DIAGNOSTIC_SEVERITY_UNSPECIFIED), "DIAGNOSTIC_SEVERITY_UNSPECIFIED"},
		{"DIAGNOSTIC_SEVERITY_ERROR", int32(pluginv1.DiagnosticSeverity_DIAGNOSTIC_SEVERITY_ERROR), "DIAGNOSTIC_SEVERITY_ERROR"},
		{"DIAGNOSTIC_SEVERITY_WARNING", int32(pluginv1.DiagnosticSeverity_DIAGNOSTIC_SEVERITY_WARNING), "DIAGNOSTIC_SEVERITY_WARNING"},
		{"DIAGNOSTIC_SEVERITY_INFO", int32(pluginv1.DiagnosticSeverity_DIAGNOSTIC_SEVERITY_INFO), "DIAGNOSTIC_SEVERITY_INFO"},
	}

	expectedNumbers := map[string]int32{
		"SEVERITY_UNSPECIFIED":            0,
		"SEVERITY_CRITICAL":              1,
		"SEVERITY_HIGH":                  2,
		"SEVERITY_MEDIUM":                3,
		"SEVERITY_LOW":                   4,
		"SEVERITY_INFO":                  5,
		"CONFIDENCE_UNSPECIFIED":          0,
		"CONFIDENCE_HIGH":                1,
		"CONFIDENCE_MEDIUM":              2,
		"CONFIDENCE_LOW":                 3,
		"ARTIFACT_TYPE_UNSPECIFIED":       0,
		"ARTIFACT_TYPE_SOURCE":            1,
		"ARTIFACT_TYPE_CONFIG":            2,
		"ARTIFACT_TYPE_LOCKFILE":          3,
		"ARTIFACT_TYPE_CONTAINER":         4,
		"ARTIFACT_TYPE_AI_COMPONENT":      5,
		"ARTIFACT_TYPE_UNKNOWN":           6,
		"DIAGNOSTIC_SEVERITY_UNSPECIFIED": 0,
		"DIAGNOSTIC_SEVERITY_ERROR":       1,
		"DIAGNOSTIC_SEVERITY_WARNING":     2,
		"DIAGNOSTIC_SEVERITY_INFO":        3,
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wantNum, ok := expectedNumbers[tt.str]
			if !ok {
				t.Fatalf("no expected number for %q", tt.str)
			}
			if tt.enum != wantNum {
				t.Errorf("%s: numeric value got %d, want %d", tt.str, tt.enum, wantNum)
			}
		})
	}
}

func TestZeroValueSafety(t *testing.T) {
	messages := []proto.Message{
		&pluginv1.Location{},
		&pluginv1.Finding{},
		&pluginv1.Artifact{},
		&pluginv1.Package{},
		&pluginv1.AIComponent{},
		&pluginv1.GetManifestRequest{},
		&pluginv1.GetManifestResponse{},
		&pluginv1.Capability{},
		&pluginv1.ToolDef{},
		&pluginv1.ResourceDef{},
		&pluginv1.SafetyRequirements{},
		&pluginv1.InvokeToolRequest{},
		&pluginv1.InvokeToolResponse{},
		&pluginv1.Diagnostic{},
		&pluginv1.StreamArtifactsRequest{},
		&pluginv1.StreamArtifactsResponse{},
	}

	for _, msg := range messages {
		name := string(msg.ProtoReflect().Descriptor().Name())
		t.Run(name, func(t *testing.T) {
			data, err := proto.Marshal(msg)
			if err != nil {
				t.Fatalf("marshal empty %s: %v", name, err)
			}
			out := msg.ProtoReflect().New().Interface()
			if err := proto.Unmarshal(data, out); err != nil {
				t.Fatalf("unmarshal empty %s: %v", name, err)
			}
		})
	}
}
