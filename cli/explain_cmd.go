package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/felixgeelhaar/hardline/assist"
	hardline "github.com/felixgeelhaar/hardline/core"
)

// runExplain runs a scan and generates LLM-powered explanations of findings.
func runExplain(args []string) int {
	fs := flag.NewFlagSet("explain", flag.ContinueOnError)

	var (
		model     string
		baseURL   string
		batchSize int
		output    string
	)

	fs.StringVar(&model, "model", "gpt-4o", "LLM model name")
	fs.StringVar(&baseURL, "base-url", "", "custom OpenAI-compatible API base URL")
	fs.IntVar(&batchSize, "batch-size", 10, "findings per LLM request")
	fs.StringVar(&output, "output", "explanations.json", "output file path")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "Usage: hardline explain <path> [flags]")
		return 2
	}
	target := fs.Arg(0)

	// Check for API key.
	if os.Getenv("OPENAI_API_KEY") == "" && baseURL == "" {
		fmt.Fprintln(os.Stderr, "error: OPENAI_API_KEY environment variable is required (or set --base-url for a local endpoint)")
		return 2
	}

	// Run scan.
	fmt.Printf("hardline — scanning %s\n", target)
	result, err := hardline.RunScan(target)
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
	provider := assist.NewOpenAIProvider(providerOpts...)

	// Build explainer.
	var explainerOpts []assist.Option
	if batchSize > 0 {
		explainerOpts = append(explainerOpts, assist.WithBatchSize(batchSize))
	}
	explainer := assist.NewExplainer(provider, explainerOpts...)

	// Generate explanations.
	fmt.Println("[explain] generating explanations...")
	report, err := explainer.Explain(context.Background(), result)
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
