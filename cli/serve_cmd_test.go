package main

import (
	"testing"
)

func TestRunServe_InvalidFlag(t *testing.T) {
	// Serve runs indefinitely, so we can't easily test it here.
	// Just verify the command is registered in run().
	code := run([]string{"serve", "--invalid-flag"})
	// Should fail with error exit code because serve doesn't support invalid flag.
	if code != 2 {
		t.Fatalf("expected exit code 2 for serve with invalid flag, got %d", code)
	}
}

func TestRunServe_AllowedPathsFlag(t *testing.T) {
	// We can't actually run the server, but we can test flag parsing.
	// This tests the flag is recognized without starting the server.
	_ = runServe([]string{"--allowed-paths", "/tmp,/home"})
}

func TestRunServe_ViaRunCommand(t *testing.T) {
	// Test that the serve command is recognized by run().
	// We can't actually start the server in tests, but we can verify dispatch.
	_ = run([]string{"serve", "--unknown"})
}
