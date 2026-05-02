module example.com/nox-demo/multi-stack/api

go 1.25

// This is a demo module intentionally NOT wired up to a working
// build. It exists so nox can read it as a Go file with imports
// the AIBOM detector recognises, without polluting the nox root
// module's dependency graph.
//
// Run `nox scan .` from the parent examples/multi-stack/ directory
// to see polyglot AIBOM output covering this Go code plus the
// TypeScript frontend.

require github.com/anthropics/anthropic-sdk-go v0.0.0
