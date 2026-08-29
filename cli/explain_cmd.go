package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nox-hq/nox/assist"
	nox "github.com/nox-hq/nox/core"
	"github.com/nox-hq/nox/plugin"
)

// runExplain runs a scan and generates LLM-powered explanations of findings.
func runExplain(args []string) int {
	// Extract positional args (paths) before parsing flags so that
	// "nox explain . --model gpt-4o" works like "nox explain --model gpt-4o .".
	var flagArgs []string
	var positionalArgs []string
	for i := 0; i < len(args); i++ {
		if strings.HasPrefix(args[i], "-") {
			flagArgs = append(flagArgs, args[i])
			// If this flag takes a value (not a boolean), consume the next arg too.
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				i++
				flagArgs = append(flagArgs, args[i])
			}
		} else {
			positionalArgs = append(positionalArgs, args[i])
		}
	}

	fs := flag.NewFlagSet("explain", flag.ContinueOnError)
	ef := registerExplainFlags(fs)

	if err := fs.Parse(flagArgs); err != nil {
		return 2
	}
	positionalArgs = append(positionalArgs, fs.Args()...)

	if len(positionalArgs) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: nox explain <path> [flags]")
		return 2
	}
	target := positionalArgs[0]

	// Load project config and apply defaults (CLI flags take precedence).
	cfg, err := nox.LoadScanConfig(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: loading .nox.yaml: %v\n", err)
		return 2
	}
	applyExplainDefaults(fs, cfg)

	// Read the settled values only after config has filled in the flags left
	// absent — flag > config > default is complete at this point.
	model, baseURL, batchSize := ef.model, ef.baseURL, ef.batchSize
	output, pluginDir, enrich, timeout := ef.output, ef.pluginDir, ef.enrich, ef.timeout

	// Check for API key.
	apiKeyEnv := "OPENAI_API_KEY"
	if cfg.Explain.APIKeyEnv != "" {
		apiKeyEnv = cfg.Explain.APIKeyEnv
	}
	if os.Getenv(apiKeyEnv) == "" && baseURL == "" {
		fmt.Fprintf(os.Stderr, "error: %s environment variable is required (or set --base-url for a local endpoint)\n", apiKeyEnv)
		return 2
	}

	// Run scan.
	fmt.Printf("nox — scanning %s\n", target)
	result, err := nox.RunScan(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: scan failed: %v\n", err)
		return 2
	}

	findingCount := len(result.Findings.Findings())
	fmt.Printf("[results] %d findings\n", findingCount)

	if findingCount == 0 {
		fmt.Println("[explain] no findings to explain")
		return 0
	}

	// Build provider.
	var providerOpts []assist.OpenAIOption
	providerOpts = append(providerOpts, assist.WithModel(model))
	if baseURL != "" {
		providerOpts = append(providerOpts, assist.WithBaseURL(baseURL))
	}
	providerOpts = append(providerOpts, assist.WithTimeout(timeout))
	provider := assist.NewOpenAIProvider(providerOpts...)

	// Build explainer.
	var explainerOpts []assist.Option
	if batchSize > 0 {
		explainerOpts = append(explainerOpts, assist.WithBatchSize(batchSize))
	}

	// Wire plugin source if --plugin-dir is set.
	var pluginHost *plugin.Host
	if pluginDir != "" {
		pluginHost = plugin.NewHost()
		defer func() { _ = pluginHost.Close() }()

		entries, err := os.ReadDir(pluginDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: reading plugin dir %s: %v\n", pluginDir, err)
			return 2
		}

		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			binPath := filepath.Join(pluginDir, entry.Name())
			if err := pluginHost.RegisterBinary(context.Background(), binPath, nil); err != nil {
				fmt.Fprintf(os.Stderr, "warning: plugin %s failed to register: %v\n", entry.Name(), err)
				continue
			}
			fmt.Printf("[plugins] registered %s\n", entry.Name())
		}

		adapter := assist.NewHostAdapter(pluginHost, target)
		explainerOpts = append(explainerOpts, assist.WithPluginSource(adapter))
	}

	// Wire enrichment tools if --enrich is set.
	if enrich != "" {
		tools := strings.Split(enrich, ",")
		for i := range tools {
			tools[i] = strings.TrimSpace(tools[i])
		}
		explainerOpts = append(explainerOpts, assist.WithEnrichmentTools(tools...))
	}

	explainerOpts = append(explainerOpts, assist.WithBasePath(target))
	explainer := assist.NewExplainer(provider, explainerOpts...)

	// Generate explanations with timeout.
	fmt.Println("[explain] generating explanations...")
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	report, err := explainer.Explain(ctx, result)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: explain failed: %v\n", err)
		return 2
	}

	// Write report.
	if err := report.WriteFile(output); err != nil {
		fmt.Fprintf(os.Stderr, "error: writing %s: %v\n", output, err)
		return 2
	}

	fmt.Printf("[explain] wrote %s (%d explanations)\n", output, len(report.Explanations))
	if report.Summary != "" {
		fmt.Printf("[summary] %s\n", report.Summary)
	}
	fmt.Println("[done]")
	return 0
}

// explainFlags holds the explain command's flag-backed settings. Every field is
// dual-source: settable on the command line and under `explain:` in .nox.yaml.
type explainFlags struct {
	model     string
	baseURL   string
	batchSize int
	output    string
	pluginDir string
	enrich    string
	timeout   time.Duration
}

// registerExplainFlags binds the explain flags onto fs and returns their
// destinations. Registration is a single function so the precedence contract
// tests exercise the real flag names, types and defaults instead of a
// hand-rolled copy — a copy had already drifted (it declared -timeout as a
// string where production registers a Duration), and a test built on a
// different flag set cannot catch a precedence bug in the real one.
func registerExplainFlags(fs *flag.FlagSet) *explainFlags {
	f := &explainFlags{}
	fs.StringVar(&f.model, "model", "gpt-4o", "LLM model name")
	fs.StringVar(&f.baseURL, "base-url", "", "custom OpenAI-compatible API base URL")
	fs.IntVar(&f.batchSize, "batch-size", 10, "findings per LLM request")
	fs.StringVar(&f.output, "output", "explanations.json", "output file path")
	fs.StringVar(&f.pluginDir, "plugin-dir", "", "directory containing plugin binaries for enrichment")
	fs.StringVar(&f.enrich, "enrich", "", "comma-separated list of read-only plugin tools to invoke for enrichment")
	fs.DurationVar(&f.timeout, "timeout", 2*time.Minute, "timeout per LLM request")
	return f
}

// applyExplainDefaults applies .nox.yaml explain settings as defaults for any
// flags that were not explicitly set on the command line.
func applyExplainDefaults(fs *flag.FlagSet, cfg *nox.ScanConfig) {
	ec := cfg.Explain
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })

	if !set["model"] && ec.Model != "" {
		_ = fs.Set("model", ec.Model)
	}
	if !set["base-url"] && ec.BaseURL != "" {
		_ = fs.Set("base-url", ec.BaseURL)
	}
	if !set["timeout"] && ec.Timeout != "" {
		_ = fs.Set("timeout", ec.Timeout)
	}
	if !set["batch-size"] && ec.BatchSize > 0 {
		_ = fs.Set("batch-size", fmt.Sprintf("%d", ec.BatchSize))
	}
	if !set["output"] && ec.Output != "" {
		_ = fs.Set("output", ec.Output)
	}
	if !set["enrich"] && ec.Enrich != "" {
		_ = fs.Set("enrich", ec.Enrich)
	}
	if !set["plugin-dir"] && ec.PluginDir != "" {
		_ = fs.Set("plugin-dir", ec.PluginDir)
	}
}
