package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nox-hq/nox/registry"
)

func TestBuildInitData_CoreAnalysis(t *testing.T) {
	t.Parallel()

	data := buildInitData("nox/sast", registry.TrackCoreAnalysis, "")

	if data.Name != "nox/sast" {
		t.Errorf("Name = %q, want %q", data.Name, "nox/sast")
	}
	if data.ModuleName != "nox-plugin-sast" {
		t.Errorf("ModuleName = %q, want %q", data.ModuleName, "nox-plugin-sast")
	}
	if data.DisplayName != "Sast" {
		t.Errorf("DisplayName = %q, want %q", data.DisplayName, "Sast")
	}
	if data.Track != "core-analysis" {
		t.Errorf("Track = %q, want %q", data.Track, "core-analysis")
	}
	if data.RiskClass != "passive" {
		t.Errorf("RiskClass = %q, want %q", data.RiskClass, "passive")
	}
	if data.ReadOnly != "true" {
		t.Errorf("ReadOnly = %q, want %q", data.ReadOnly, "true")
	}
	if data.CapabilityName != "sast" {
		t.Errorf("CapabilityName = %q, want %q", data.CapabilityName, "sast")
	}
}

func TestBuildInitData_ShortName(t *testing.T) {
	t.Parallel()

	// Name without slash should use the full name as shortName.
	data := buildInitData("myplugin", registry.TrackCoreAnalysis, "")

	if data.ModuleName != "nox-plugin-myplugin" {
		t.Errorf("ModuleName = %q, want %q", data.ModuleName, "nox-plugin-myplugin")
	}
	if data.DisplayName != "Myplugin" {
		t.Errorf("DisplayName = %q, want %q", data.DisplayName, "Myplugin")
	}
}

func TestBuildInitData_RiskClassOverride(t *testing.T) {
	t.Parallel()

	data := buildInitData("nox/test", registry.TrackCoreAnalysis, "active")

	if data.RiskClass != "active" {
		t.Errorf("RiskClass = %q, want %q", data.RiskClass, "active")
	}
	if data.ReadOnly != "false" {
		t.Errorf("ReadOnly = %q, want %q", data.ReadOnly, "false")
	}
}

func TestBuildInitData_RuntimeRiskClass(t *testing.T) {
	t.Parallel()

	data := buildInitData("nox/test", registry.TrackCoreAnalysis, "runtime")

	if data.RiskClass != "runtime" {
		t.Errorf("RiskClass = %q, want %q", data.RiskClass, "runtime")
	}
	if data.ReadOnly != "false" {
		t.Errorf("ReadOnly = %q, want %q", data.ReadOnly, "false")
	}
}

func TestBuildInitData_DynamicRuntimeTrack(t *testing.T) {
	t.Parallel()

	data := buildInitData("nox/drt", registry.TrackDynamicRuntime, "")

	// Dynamic runtime track has active risk class by default.
	if data.RiskClass != "active" {
		t.Errorf("RiskClass = %q, want %q", data.RiskClass, "active")
	}
	if data.ReadOnly != "false" {
		t.Errorf("ReadOnly = %q, want %q", data.ReadOnly, "false")
	}
}

func TestBuildSafetyOpts_Passive(t *testing.T) {
	t.Parallel()

	opts := buildSafetyOpts(registry.TrackCoreAnalysis, "passive")
	if !strings.Contains(opts, "sdk.WithRiskClass(sdk.RiskPassive)") {
		t.Errorf("expected RiskPassive in opts: %q", opts)
	}
}

func TestBuildSafetyOpts_Active(t *testing.T) {
	t.Parallel()

	opts := buildSafetyOpts(registry.TrackCoreAnalysis, "active")
	if !strings.Contains(opts, "sdk.WithRiskClass(sdk.RiskActive)") {
		t.Errorf("expected RiskActive in opts: %q", opts)
	}
}

func TestBuildSafetyOpts_Runtime(t *testing.T) {
	t.Parallel()

	opts := buildSafetyOpts(registry.TrackCoreAnalysis, "runtime")
	if !strings.Contains(opts, "sdk.WithRiskClass(sdk.RiskRuntime)") {
		t.Errorf("expected RiskRuntime in opts: %q", opts)
	}
}

func TestBuildSafetyOpts_DynamicRuntimeTrack(t *testing.T) {
	t.Parallel()

	opts := buildSafetyOpts(registry.TrackDynamicRuntime, "active")
	if !strings.Contains(opts, "sdk.WithNeedsConfirmation()") {
		t.Errorf("expected WithNeedsConfirmation in opts: %q", opts)
	}
	if !strings.Contains(opts, `sdk.WithNetworkHosts("localhost")`) {
		t.Errorf("expected localhost network host in opts: %q", opts)
	}
}

func TestBuildSafetyOpts_SupplyChainTrack(t *testing.T) {
	t.Parallel()

	opts := buildSafetyOpts(registry.TrackSupplyChain, "passive")
	if !strings.Contains(opts, "*.osv.dev") {
		t.Errorf("expected osv.dev host in opts: %q", opts)
	}
	if !strings.Contains(opts, "*.github.com") {
		t.Errorf("expected github.com host in opts: %q", opts)
	}
}

func TestBuildSafetyOpts_IntelligenceTrack(t *testing.T) {
	t.Parallel()

	opts := buildSafetyOpts(registry.TrackIntelligence, "passive")
	if !strings.Contains(opts, "*.osv.dev") {
		t.Errorf("expected osv.dev host in opts: %q", opts)
	}
	if !strings.Contains(opts, "*.nvd.nist.gov") {
		t.Errorf("expected nvd.nist.gov host in opts: %q", opts)
	}
}

func TestBuildSafetyOpts_AgentAssistanceTrack(t *testing.T) {
	t.Parallel()

	opts := buildSafetyOpts(registry.TrackAgentAssistance, "passive")
	if !strings.Contains(opts, "*.openai.com") {
		t.Errorf("expected openai.com host in opts: %q", opts)
	}
	if !strings.Contains(opts, "*.anthropic.com") {
		t.Errorf("expected anthropic.com host in opts: %q", opts)
	}
	if !strings.Contains(opts, "OPENAI_API_KEY") {
		t.Errorf("expected OPENAI_API_KEY env var in opts: %q", opts)
	}
	if !strings.Contains(opts, "ANTHROPIC_API_KEY") {
		t.Errorf("expected ANTHROPIC_API_KEY env var in opts: %q", opts)
	}
}

func TestScaffoldPlugin(t *testing.T) {
	dir := t.TempDir()
	outDir := filepath.Join(dir, "my-plugin")

	data := buildInitData("nox/sast", registry.TrackCoreAnalysis, "")
	if err := scaffoldPlugin(outDir, &data); err != nil {
		t.Fatalf("scaffoldPlugin: %v", err)
	}

	// Verify expected files exist.
	expectedFiles := []string{
		"main.go",
		"main_test.go",
		"go.mod",
		"Makefile",
		"README.md",
		"Dockerfile",
		filepath.Join(".github", "workflows", "ci.yml"),
		filepath.Join(".github", "workflows", "release.yml"),
		".goreleaser.yaml",
		"plugin.yaml",
	}

	for _, f := range expectedFiles {
		path := filepath.Join(outDir, f)
		info, err := os.Stat(path)
		if err != nil {
			t.Errorf("expected file %s to exist: %v", f, err)
			continue
		}
		if info.Size() == 0 {
			t.Errorf("expected file %s to have content", f)
		}
	}

	// Verify testdata directory exists.
	testdataDir := filepath.Join(outDir, "testdata")
	info, err := os.Stat(testdataDir)
	if err != nil {
		t.Fatalf("testdata dir: %v", err)
	}
	if !info.IsDir() {
		t.Fatal("expected testdata to be a directory")
	}
}

func TestScaffoldPlugin_VerifyTemplateContent(t *testing.T) {
	dir := t.TempDir()
	outDir := filepath.Join(dir, "test-plugin")

	data := buildInitData("nox/sast", registry.TrackCoreAnalysis, "")
	if err := scaffoldPlugin(outDir, &data); err != nil {
		t.Fatalf("scaffoldPlugin: %v", err)
	}

	// Verify go.mod contains module name.
	goMod, err := os.ReadFile(filepath.Join(outDir, "go.mod"))
	if err != nil {
		t.Fatalf("reading go.mod: %v", err)
	}
	if !strings.Contains(string(goMod), "nox-plugin-sast") {
		t.Errorf("go.mod should contain module name, got: %s", string(goMod))
	}

	// Verify main.go contains plugin data.
	mainGo, err := os.ReadFile(filepath.Join(outDir, "main.go"))
	if err != nil {
		t.Fatalf("reading main.go: %v", err)
	}
	if !strings.Contains(string(mainGo), "sast") {
		t.Errorf("main.go should reference plugin capability")
	}
}

func TestScaffoldPlugin_CreatesDirIfMissing(t *testing.T) {
	dir := t.TempDir()
	outDir := filepath.Join(dir, "nested", "deep", "plugin")

	data := buildInitData("nox/test", registry.TrackCoreAnalysis, "")
	if err := scaffoldPlugin(outDir, &data); err != nil {
		t.Fatalf("scaffoldPlugin: %v", err)
	}

	if _, err := os.Stat(outDir); os.IsNotExist(err) {
		t.Fatal("expected output directory to be created")
	}
}

func TestRunPluginInit_MissingName(t *testing.T) {
	code := runPluginInit([]string{})
	if code != 2 {
		t.Fatalf("expected exit code 2 for missing name, got %d", code)
	}
}

func TestRunPluginInit_MissingTrack(t *testing.T) {
	code := runPluginInit([]string{"--name", "nox/test"})
	if code != 2 {
		t.Fatalf("expected exit code 2 for missing track, got %d", code)
	}
}

func TestRunPluginInit_InvalidTrack(t *testing.T) {
	code := runPluginInit([]string{"--name", "nox/test", "--track", "nonexistent-track"})
	if code != 2 {
		t.Fatalf("expected exit code 2 for invalid track, got %d", code)
	}
}

func TestRunPluginInit_InvalidFlag(t *testing.T) {
	code := runPluginInit([]string{"--invalid-flag"})
	if code != 2 {
		t.Fatalf("expected exit code 2 for invalid flag, got %d", code)
	}
}

func TestRunPluginInit_Success(t *testing.T) {
	dir := t.TempDir()
	outDir := filepath.Join(dir, "test-output")

	code := runPluginInit([]string{
		"--name", "nox/sast",
		"--track", "core-analysis",
		"--output", outDir,
	})
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}

	// Verify files were created.
	if _, err := os.Stat(filepath.Join(outDir, "main.go")); err != nil {
		t.Fatalf("main.go should exist: %v", err)
	}
}

func TestRunPluginInit_SuccessDefaultOutput(t *testing.T) {
	dir := t.TempDir()

	// Change to temp dir so the default output lands there.
	oldDir, _ := os.Getwd()
	defer func() { _ = os.Chdir(oldDir) }()
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("os.Chdir: %v", err)
	}

	code := runPluginInit([]string{
		"--name", "nox/sast",
		"--track", "core-analysis",
	})
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}

	// Default output directory should be derived from name.
	if _, err := os.Stat(filepath.Join(dir, "nox-plugin-sast", "main.go")); err != nil {
		t.Fatalf("expected default output dir: %v", err)
	}
}

func TestRunPluginInit_WithRiskClass(t *testing.T) {
	dir := t.TempDir()
	outDir := filepath.Join(dir, "test-plugin")

	code := runPluginInit([]string{
		"--name", "nox/drt",
		"--track", "dynamic-runtime",
		"--risk-class", "runtime",
		"--output", outDir,
	})
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
}

func TestRunPluginInit_ViaRunCommand(t *testing.T) {
	dir := t.TempDir()
	outDir := filepath.Join(dir, "test-plugin")

	code := run([]string{"plugin", "init", "--name", "nox/test", "--track", "core-analysis", "--output", outDir})
	if code != 0 {
		t.Fatalf("expected exit code 0 via run, got %d", code)
	}
}

// The scaffold used to generate the old shared pipeline: Go 1.25, a
// golangci-lint built with Go 1.25, Ed25519 signing via NOX_SIGNING_KEY, and
// the SDK pinned to nox v0.1.0. nox-plugin-freshness was generated from it,
// sat red in CI from the day it was created, and could not have produced a
// release the registry verifies. Nothing generated may point back at it.
func TestScaffoldGeneratesTheFleetPipeline(t *testing.T) {
	dir := t.TempDir()
	data := buildInitData("nox/demo", registry.TrackSupplyChain, "")
	if err := scaffoldPlugin(dir, &data); err != nil {
		t.Fatalf("scaffoldPlugin: %v", err)
	}
	var all strings.Builder
	for _, f := range []string{".github/workflows/ci.yml", ".github/workflows/release.yml", ".goreleaser.yaml", "go.mod", "plugin.yaml"} {
		b, err := os.ReadFile(filepath.Join(dir, f))
		if err != nil {
			t.Fatalf("reading %s: %v", f, err)
		}
		all.Write(b)
	}
	out := all.String()
	for _, stale := range []string{"nox-hq/.github/", "NOX_SIGNING_KEY", "go-version: '1.25'", "nox v0.1.0", "go 1.25\n"} {
		if strings.Contains(out, stale) {
			t.Errorf("scaffold still generates %q from the old shared pipeline", stale)
		}
	}
	for _, want := range []string{"goreleaser", "cosign", "checksums.txt.sigstore.json", "track: supply-chain", "go-version-file: go.mod"} {
		if !strings.Contains(out, want) {
			t.Errorf("scaffold is missing %q from the fleet pipeline", want)
		}
	}
	// The generated text must be valid after templating: no Go template
	// markers left over, and GitHub/GoReleaser expressions preserved.
	// GoReleaser's own {{.Version}} is meant to survive; ours are not.
	for _, field := range []string{"{{.ModuleName", "{{.Name", "{{.Track", "{{.Nox", "{{.Go", "{{.Description", "{{.Capability"} {
		if strings.Contains(out, field) {
			t.Errorf("scaffold field %s survived unrendered", field)
		}
	}
	if !strings.Contains(out, "${{ secrets.GITHUB_TOKEN }}") || !strings.Contains(out, "{{ .Version }}") {
		t.Error("GitHub or GoReleaser expressions were consumed by the Go template instead of preserved")
	}
}

func TestScaffoldPinsTheReleaseThatGeneratedIt(t *testing.T) {
	const c = "f345910099d0d7404f15fb4a55a8a826af6f824e"
	if got := scaffoldNoxVersion("1.38.2"); got != "v1.38.2" {
		t.Errorf("release build: SDK %q, want v1.38.2", got)
	}
	if got := scaffoldNoxActionRef("1.38.2", c); got != c+" # v1.38.2" {
		t.Errorf("release build: action ref %q", got)
	}
	// A dev build names no release, so it must not guess one.
	if got := scaffoldNoxVersion("dev"); got != "" {
		t.Errorf("dev build: SDK %q, want empty (go mod tidy resolves it)", got)
	}
	if got := scaffoldNoxActionRef("dev", "none"); got != "v1" {
		t.Errorf("dev build: action ref %q, want v1", got)
	}
}
