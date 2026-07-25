package confirm

import (
	"path/filepath"
	"reflect"
	"testing"
)

func TestRecoverEntryPointFromSource(t *testing.T) {
	for _, name := range []string{"vulnerable_app.py", "fixed_app.py"} {
		t.Run(name, func(t *testing.T) {
			ep, err := RecoverEntryPointFromSource(filepath.Join("testdata", name), "chat")
			if err != nil {
				t.Fatalf("recover: %v", err)
			}
			if ep.Route != "/chat" {
				t.Errorf("route = %q, want /chat", ep.Route)
			}
			if !reflect.DeepEqual(ep.Fields, []string{"persona", "message"}) {
				t.Errorf("fields = %v, want [persona message]", ep.Fields)
			}
		})
	}
}

func TestRecoverEntryPoint_MissingFunction(t *testing.T) {
	_, err := RecoverEntryPointFromSource(filepath.Join("testdata", "vulnerable_app.py"), "nonexistent")
	if err == nil {
		t.Fatal("expected error for missing function")
	}
}

func TestRecoverEntryPoint_HealthRoute(t *testing.T) {
	// The health handler has a route but reads no request fields.
	ep, err := RecoverEntryPointFromSource(filepath.Join("testdata", "vulnerable_app.py"), "health")
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if ep.Route != "/health" {
		t.Errorf("route = %q, want /health", ep.Route)
	}
	if len(ep.Fields) != 0 {
		t.Errorf("health handler should read no fields, got %v", ep.Fields)
	}
}
