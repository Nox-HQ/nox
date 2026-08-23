package main

import (
	"testing"
)

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
