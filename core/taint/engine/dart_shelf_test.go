package engine

import (
	"slices"
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// analyzeDartFile runs the same-file pipeline over Dart source.
func analyzeDartFile(t *testing.T, src string) []string {
	t.Helper()
	eng := NewStructuralEngine(nil)
	return ruleIDs(eng.AnalyzeFile(ExtractUnits("t.dart", lexctx.LangDart, []byte(src))))
}

// TestDartShelfRequestSources: every way a shelf handler reads attacker input
// must reach its sink, and a twin that has the same real source but only uses a
// constant (a fixed path, or a sanitized value) must stay clean. A twin with no
// source guards nothing, so every twin below reads the request.
func TestDartShelfRequestSources(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []string
	}{
		{"url.queryParameters", `Future<Response> h(Request request) async {
  final name = request.url.queryParameters['file'];
  final d = await File(name!).readAsString();
  return Response.ok(d);
}
`, []string{"TAINT-004"}},
		{"url.queryParameters via req alias", `Future<Response> h(Request req) async {
  final name = req.url.queryParameters['file'];
  final d = await File(name!).readAsString();
  return Response.ok(d);
}
`, []string{"TAINT-004"}},
		{"requestedUri.queryParameters", `Future<Response> h(Request request) async {
  final f = request.requestedUri.queryParameters['f']!;
  return Response.ok(await File(f).readAsString());
}
`, []string{"TAINT-004"}},
		{"readAsString body to Process.run", `Future<Response> h(Request request) async {
  final body = await request.readAsString();
  await Process.run('sh', ['-c', body]);
  return Response.ok('ok');
}
`, []string{"TAINT-002"}},
		{"headers", `Future<Response> h(Request request) async {
  final f = request.headers['x-file']!;
  final d = await File(f).readAsString();
  return Response.ok(d);
}
`, []string{"TAINT-004"}},
		{"shelf_router inline path param", `Router build() {
  final app = Router();
  app.get('/u/<id>', (Request req, String id) async {
    final d = await File(id).readAsString();
    return Response.ok(d);
  });
  return app;
}
`, []string{"TAINT-004"}},
		{"shelf_router named handler path param", `Future<Response> userHandler(Request request, String id) async {
  final d = await File(id).readAsString();
  return Response.ok(d);
}
`, []string{"TAINT-004"}},
		// Safe twins: the request IS read, the sink argument is not derived from it.
		{"constant path, query read", `Future<Response> h(Request request) async {
  final x = request.url.queryParameters['file'];
  final d = await File('/srv/static/fixed.txt').readAsString();
  return Response.ok(d + (x ?? ''));
}
`, nil},
		{"constant path, path param read", `Router build() {
  final app = Router();
  app.get('/u/<id>', (Request req, String id) async {
    final d = await File('/srv/static/fixed.txt').readAsString();
    return Response.ok(d + id);
  });
  return app;
}
`, nil},
		{"int.parse sanitizes the path param", `Future<Response> userHandler(Request request, String id) async {
  final n = int.parse(id);
  final d = await File('/srv/u/$n').readAsString();
  return Response.ok(d);
}
`, nil},
		// A String parameter of a function with no Request is not a route param.
		{"plain String param is not a source", `Future<String> load(String id) async {
  return await File(id).readAsString();
}
`, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := analyzeDartFile(t, tt.src); !slices.Equal(got, tt.want) {
				t.Fatalf("flows = %v, want %v", got, tt.want)
			}
		})
	}
}
