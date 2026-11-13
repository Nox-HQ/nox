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
		{"demo.ipynb", "{\"outputs\": [{\"data\": {\n   \"image/png\": \"iVBORw0KGgoAAAANSUhEUgAA" + filler + "+" + token + "/" + filler + "\",\n}}]}\n"},
		{"fixture.json", "{\"mime_type\": \"image/jpeg\",\n \"data\": \"/9j/4AAQSkZJRgABAQEBLAEsAAD" + filler + "+" + token + "/" + filler + "\"}\n"},
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

// A YAML cassette stores a generated image as a plain scalar — `result:
// iVBORw0KGgo…` with no quotes — so the quoted-string check never saw it.
// pydantic-ai's image-generation cassette is one 2.9 MB line of this and
// fired SEC-055 234 times and SEC-048 153 times (#930).
func TestAMatchInsideAnUnquotedYAMLImageScalarIsImageData(t *testing.T) {
	nuget := "oy2" + strings.Repeat("ab3de5fg7h", 5)[:43]
	cargo := "cio" + strings.Repeat("Ab3De5Fg7H", 4)[:32]
	filler := strings.Repeat("AAAAQABAAD", 12)
	// Base64 carries + and /, which are word boundaries, so a vendor window
	// between them satisfies an anchored pattern: only the image refiner can
	// tell it from a credential.
	for _, tok := range []struct{ rule, value string }{{"SEC-048", nuget}, {"SEC-055", cargo}} {
		src := "interactions:\n- response:\n    output:\n      result: iVBORw0KGgoAAAANSUhEUgAA" +
			filler + "+" + tok.value + "/" + filler + "\n      quality: low\n"
		if reports(t, "cassette.yaml", src, tok.rule) {
			t.Errorf("%s reported inside an unquoted base64 image scalar", tok.rule)
		}
		// The same value as a scalar of its own is still a credential.
		if !reports(t, "publish.yaml", "registry:\n  token: "+tok.value+"\n", tok.rule) {
			t.Errorf("%s no longer reports its credential as a plain YAML scalar", tok.rule)
		}
	}
}
