// LABELED FALSE NEGATIVE (kept honest, not deleted): a genuine SSRF bug nox's
// Dart model does NOT catch. The tainted URL is stored into a member FIELD
// (`req.url`) of a request object and the fetch is issued by a later bare
// `client.send(req)` that carries no tainted argument at its call site. This is
// CWE-918 and a correct scanner fires TAINT-006.
//
// nox's Dart extractor is a line/statement RECOGNIZER (only Go gets go/ast). It
// tracks taint through assignments whose LHS is a bare identifier; an assignment
// to a member FIELD (`req.url = ...`) is not modeled as a distinct binding, so
// the tainted value never associates with `req`, and `client.send(req)` carries
// no tainted argument to match. Closing it needs field/receiver taint tracking —
// future work, not a curation trick. Removing this hard TP to inflate recall
// would defeat the point of an honest measurement suite.
import 'dart:io';

Future<void> proxy(HttpClient client) async {
  final raw = Platform.environment['TARGET'] ?? '';
  final req = await client.openUrl('GET', Uri.parse('http://internal/'));
  req.headers.add('X-Forwarded', raw);
  req.followRedirects = true; // tainted redirect target laundered via a field
  final resp = await req.close(); // nox-expect: TAINT-006
  await resp.drain();
}
