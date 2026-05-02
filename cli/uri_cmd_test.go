package main

import (
	"strings"
	"testing"
)

func TestURIIsSafePluginName(t *testing.T) {
	good := []string{"nox/ai-eval", "nox/reachability", "acme/secret-scanner-v2"}
	bad := []string{"", "../etc", "foo;bar", ".hidden", "-leading-dash", "/leading-slash", strings.Repeat("a", 201)}
	for _, n := range good {
		if !uriIsSafePluginName(n) {
			t.Errorf("safe rejected: %q", n)
		}
	}
	for _, n := range bad {
		if uriIsSafePluginName(n) {
			t.Errorf("unsafe accepted: %q", n)
		}
	}
}

func TestURIIsSafeVersion(t *testing.T) {
	good := []string{"1.2.3", "v1.2.3", ">=0.5", "1.0.0-beta+build", "^1.0.0"}
	bad := []string{"1.2;rm -rf", "$(x)", "../1.0", "1`whoami`"}
	for _, v := range good {
		if !uriIsSafeVersion(v) {
			t.Errorf("safe version rejected: %q", v)
		}
	}
	for _, v := range bad {
		if uriIsSafeVersion(v) {
			t.Errorf("unsafe version accepted: %q", v)
		}
	}
}

func TestRunURIDispatch_RejectsNonNoxScheme(t *testing.T) {
	rc := runURIDispatch("https://example.com")
	if rc == 0 {
		t.Error("expected non-zero exit for non-nox scheme")
	}
}

func TestRunURIDispatch_UnknownAction(t *testing.T) {
	rc := runURIDispatch("nox://wat")
	if rc == 0 {
		t.Error("expected non-zero exit for unknown action")
	}
}
