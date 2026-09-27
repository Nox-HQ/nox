package secrets

import (
	"strings"
	"testing"
)

// A notebook output or a recorded response carries images as base64 strings
// without a data: prefix — "image/png": "iVBORw0KGgo…", "data": "/9j/4AAQ…".
// Any long enough base64 run contains any short vendor prefix, so rules like
// SEC-048 (NuGet, oy2 + 43) fired inside them: 157 findings on the 2026-09-27
// head-to-head benchmark, in llama_index notebooks and vercel/ai fixtures.
func TestAMatchInsideABase64ImageIsImageData(t *testing.T) {
	token := "oy2" + strings.Repeat("aB3dE5fG7h", 5)[:43]
	filler := strings.Repeat("AAAAQABAAD", 12)
	for _, c := range []struct{ name, src string }{
		{"demo.ipynb", "{\"outputs\": [{\"data\": {\n   \"image/png\": \"iVBORw0KGgoAAAANSUhEUgAA" + filler + token + filler + "\",\n}}]}\n"},
		{"fixture.json", "{\"mime_type\": \"image/jpeg\",\n \"data\": \"/9j/4AAQSkZJRgABAQEBLAEsAAD" + filler + token + filler + "\"}\n"},
	} {
		if reports(t, c.name, c.src, "SEC-048") {
			t.Errorf("%s: SEC-048 reported inside base64 image data", c.name)
		}
	}

	// The same token as a string of its own is still a NuGet key.
	if !reports(t, "nuget.json", "{\"nuget_api_key\": \""+token+"\"}\n", "SEC-048") {
		t.Error("a NuGet key in an ordinary string is no longer reported")
	}
}
