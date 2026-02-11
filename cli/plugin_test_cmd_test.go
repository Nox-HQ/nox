package main

import "testing"

func TestRunPluginTest_NotImplemented(t *testing.T) {
	code := runPluginTest([]string{})
	if code != 2 {
		t.Fatalf("expected exit code 2 for unimplemented command, got %d", code)
	}
}

func TestRunPluginTest_WithArgs(t *testing.T) {
	code := runPluginTest([]string{"some-plugin"})
	if code != 2 {
		t.Fatalf("expected exit code 2 for unimplemented command, got %d", code)
	}
}

func TestRunPluginTest_ViaPluginCommand(t *testing.T) {
	code := runPlugin([]string{"test"})
	if code != 2 {
		t.Fatalf("expected exit code 2 via plugin command, got %d", code)
	}
}
