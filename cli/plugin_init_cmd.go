package main

import (
	"embed"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/nox-hq/nox/registry"
)

//go:embed templates/*.tmpl
var templateFS embed.FS

// pluginInitData holds template variables for scaffolding a plugin project.
type pluginInitData struct {
	Name             string // e.g. "nox/sast"
	ModuleName       string // e.g. "nox-plugin-sast"
	DisplayName      string // e.g. "SAST"
	Description      string // e.g. "Static analysis extensions"
	Track            string // e.g. "core-analysis"
	TrackDisplayName string
	TrackDescription string
	RiskClass        string // e.g. "passive"
	CapabilityName   string // e.g. "sast"
	CapabilityDesc   string // e.g. "Static analysis"
	ReadOnly         string // "true" or "false"
	SafetyOpts       string // e.g. "sdk.WithRiskClass(sdk.RiskPassive)"
}

// runPluginInit scaffolds a new plugin project with track-aware templates.
func runPluginInit(args []string) int {
	fs := flag.NewFlagSet("plugin init", flag.ContinueOnError)
	var (
		name      string
		track     string
		riskClass string
		outDir    string
	)
	fs.StringVar(&name, "name", "", "plugin name (e.g. nox/sast)")
	fs.StringVar(&track, "track", "", "plugin track (e.g. core-analysis)")
	fs.StringVar(&riskClass, "risk-class", "", "risk class override (passive, active, runtime)")
	fs.StringVar(&outDir, "output", "", "output directory (default: derived from name)")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	if name == "" {
		fmt.Fprintln(os.Stderr, "Usage: nox plugin init --name <name> --track <track>")
		fmt.Fprintln(os.Stderr, "\nAvailable tracks:")
		for _, info := range registry.TrackCatalog() {
			fmt.Fprintf(os.Stderr, "  %-25s %s\n", info.Track, info.Description)
		}
		return 2
	}

	if track == "" {
		fmt.Fprintln(os.Stderr, "error: --track is required")
		fmt.Fprintln(os.Stderr, "\nAvailable tracks:")
		for _, info := range registry.TrackCatalog() {
			fmt.Fprintf(os.Stderr, "  %-25s %s\n", info.Track, info.Description)
		}
		return 2
	}

	if !registry.ValidTrack(registry.Track(track)) {
		fmt.Fprintf(os.Stderr, "error: unknown track %q\n", track)
		fmt.Fprintln(os.Stderr, "\nAvailable tracks:")
		for _, info := range registry.TrackCatalog() {
			fmt.Fprintf(os.Stderr, "  %-25s %s\n", info.Track, info.Description)
		}
		return 2
	}

	data := buildInitData(name, registry.Track(track), riskClass)

	if outDir == "" {
		outDir = data.ModuleName
	}

	if err := scaffoldPlugin(outDir, data); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	fmt.Printf("Created plugin project in %s/\n", outDir)
	fmt.Printf("  Track: %s (%s)\n", data.TrackDisplayName, data.Track)
	fmt.Printf("  Risk:  %s\n", data.RiskClass)
	fmt.Println("\nNext steps:")
	fmt.Printf("  cd %s\n", outDir)
	fmt.Println("  go mod tidy")
	fmt.Println("  make build")
	fmt.Println("  make test")
	return 0
}

// buildInitData constructs template data from name, track, and optional risk class override.
func buildInitData(name string, track registry.Track, riskClassOverride string) pluginInitData {
	// Derive module name: "nox/sast" → "nox-plugin-sast"
	parts := strings.SplitN(name, "/", 2)
	shortName := name
	if len(parts) == 2 {
		shortName = parts[1]
	}
	moduleName := "nox-plugin-" + shortName

	// Look up track info.
	var trackInfo registry.TrackInfo
	for _, info := range registry.TrackCatalog() {
		if info.Track == track {
			trackInfo = info
			break
		}
	}

	rc := trackInfo.Characteristics.RiskClass
	if riskClassOverride != "" {
		rc = riskClassOverride
	}

	readOnly := "true"
	if rc != "passive" {
		readOnly = "false"
	}

	safetyOpts := buildSafetyOpts(track, rc)

	return pluginInitData{
		Name:             name,
		ModuleName:       moduleName,
		DisplayName:      strings.ToUpper(shortName[:1]) + shortName[1:],
		Description:      trackInfo.Description,
		Track:            string(track),
		TrackDisplayName: trackInfo.DisplayName,
		TrackDescription: trackInfo.Description,
		RiskClass:        rc,
		CapabilityName:   shortName,
		CapabilityDesc:   trackInfo.DisplayName + " analysis",
		ReadOnly:         readOnly,
		SafetyOpts:       safetyOpts,
	}
}

// buildSafetyOpts generates SDK safety option code for templates.
func buildSafetyOpts(track registry.Track, riskClass string) string {
	var opts []string

	switch riskClass {
	case "active":
		opts = append(opts, "sdk.WithRiskClass(sdk.RiskActive)")
	case "runtime":
		opts = append(opts, "sdk.WithRiskClass(sdk.RiskRuntime)")
	default:
		opts = append(opts, "sdk.WithRiskClass(sdk.RiskPassive)")
	}

	switch track {
	case registry.TrackDynamicRuntime:
		opts = append(opts, "sdk.WithNeedsConfirmation()")
		opts = append(opts, `sdk.WithNetworkHosts("localhost")`)
	case registry.TrackSupplyChain:
		opts = append(opts, `sdk.WithNetworkHosts("*.osv.dev", "*.github.com")`)
	case registry.TrackIntelligence:
		opts = append(opts, `sdk.WithNetworkHosts("*.osv.dev", "*.nvd.nist.gov")`)
	case registry.TrackAgentAssistance:
		opts = append(opts, `sdk.WithNetworkHosts("*.openai.com", "*.anthropic.com")`)
		opts = append(opts, `sdk.WithEnvVars("OPENAI_API_KEY", "ANTHROPIC_API_KEY")`)
	}

	return strings.Join(opts, ",\n\t\t")
}

// scaffoldPlugin writes all template files into the output directory.
func scaffoldPlugin(outDir string, data pluginInitData) error {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("creating output directory: %w", err)
	}

	// File mappings: template name → output path
	files := []struct {
		tmpl string
		out  string
	}{
		{"templates/main.go.tmpl", "main.go"},
		{"templates/main_test.go.tmpl", "main_test.go"},
		{"templates/go.mod.tmpl", "go.mod"},
		{"templates/Makefile.tmpl", "Makefile"},
		{"templates/README.md.tmpl", "README.md"},
		{"templates/Dockerfile.tmpl", "Dockerfile"},
		{"templates/ci.yml.tmpl", filepath.Join(".github", "workflows", "ci.yml")},
		{"templates/release.yml.tmpl", filepath.Join(".github", "workflows", "release.yml")},
	}

	for _, f := range files {
		content, err := templateFS.ReadFile(f.tmpl)
		if err != nil {
			return fmt.Errorf("reading template %s: %w", f.tmpl, err)
		}

		tmpl, err := template.New(f.tmpl).Parse(string(content))
		if err != nil {
			return fmt.Errorf("parsing template %s: %w", f.tmpl, err)
		}

		outPath := filepath.Join(outDir, f.out)
		if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
			return fmt.Errorf("creating directory for %s: %w", f.out, err)
		}

		out, err := os.Create(outPath)
		if err != nil {
			return fmt.Errorf("creating %s: %w", f.out, err)
		}

		if err := tmpl.Execute(out, data); err != nil {
			out.Close()
			return fmt.Errorf("executing template %s: %w", f.tmpl, err)
		}
		out.Close()
	}

	// Create testdata directory.
	testdataDir := filepath.Join(outDir, "testdata")
	if err := os.MkdirAll(testdataDir, 0o755); err != nil {
		return fmt.Errorf("creating testdata: %w", err)
	}

	return nil
}
