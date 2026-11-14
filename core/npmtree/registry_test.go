package npmtree

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestHTTPRegistryReadsTheAbbreviatedDocumentOnce(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.EscapedPath())
		if got := r.Header.Get("Accept"); got != "application/vnd.npm.install-v1+json" {
			t.Errorf("Accept = %q", got)
		}
		switch r.URL.EscapedPath() {
		case "/express":
			_, _ = w.Write([]byte(`{"versions":{"4.22.3":{"dependencies":{"qs":"~6.16.0"},"optionalDependencies":{"fsevents":"^2"}}}}`))
		case "/@types%2fnode":
			_, _ = w.Write([]byte(`{"versions":{"22.0.0":{}}}`))
		default:
			w.WriteHeader(http.StatusTooManyRequests)
		}
	}))
	defer srv.Close()

	reg := NewHTTPRegistry(srv.URL)
	ctx := context.Background()
	for range 2 {
		rel, err := reg.Releases(ctx, "express")
		if err != nil {
			t.Fatal(err)
		}
		if want := map[string]string{"qs": "~6.16.0", "fsevents": "^2"}; !reflect.DeepEqual(rel["4.22.3"], want) {
			t.Fatalf("express 4.22.3 deps = %v, want %v", rel["4.22.3"], want)
		}
	}
	if _, err := reg.Releases(ctx, "@types/node"); err != nil {
		t.Fatalf("scoped package: %v", err)
	}
	// A refusal is an error, never an empty history.
	if _, err := reg.Releases(ctx, "left-pad"); err == nil || !strings.Contains(err.Error(), "HTTP 429") {
		t.Fatalf("HTTP 429 gave err = %v", err)
	}
	if want := []string{"/express", "/@types%2fnode", "/left-pad"}; !reflect.DeepEqual(paths, want) {
		t.Errorf("requests = %v, want %v (one per package)", paths, want)
	}
	if want := []string{"express", "@types/node", "left-pad"}; !reflect.DeepEqual(reg.Requested(), want) {
		t.Errorf("Requested() = %v, want %v", reg.Requested(), want)
	}
}
