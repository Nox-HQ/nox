// Two flows that were honest FALSE NEGATIVES until Dart opted in to the
// engine's shared-state join (class-scoped fields, top-level variables) and
// container binding (element assignment and in-place mutators such as `add`).
// Both are over-approximations that can only widen taint, so each was enabled
// only after measuring zero new findings across 1072 real Dart files
// (dart-lang/http, cfug/dio, dart-lang/shelf, flutter/samples).
//
// They replace tp_ssrf_field.dart, which was withdrawn: its comment described a
// tainted URL stored into `req.url` and fetched by `client.send(req)`, but its
// code used a CONSTANT URL and put the tainted value in a request HEADER, so the
// annotated CWE-918 did not hold for the code as written. Its premise is also
// not realizable in Dart — `HttpClientRequest` exposes no settable URL field,
// and across 1213 real Dart files there is not one `request.url = ...`
// assignment. Correct SSRF coverage lives in tp_ssrf.dart.
import 'dart:io';

// Cross-method flow through an INSTANCE FIELD. The source lands in `target` in
// one method and the sink reads it in another. A field declared in the class
// body is shared state for that class's methods only (the same field name in
// another class is a different variable), and `this.target` is the same name.
class Fetcher {
  String target = '';

  void configure() {
    target = Platform.environment['TARGET'] ?? '';
  }

  Future<void> run(HttpClient client) async {
    final req = await client.getUrl(Uri.parse(target)); // nox-expect: TAINT-006
    await req.close();
  }
}

// Taint laundered through a LIST ELEMENT. `urls.add(x)` is a store into the
// container with no `=` for the assignment recognizer to see; it is modeled as
// a rebinding of `urls` that keeps what the list already held, so the later
// element read carries the taint (container-level, not per element).
Future<void> fetchFirst(HttpClient client) async {
  final urls = <String>[];
  urls.add(Platform.environment['TARGET'] ?? '');
  final req = await client.getUrl(Uri.parse(urls[0])); // nox-expect: TAINT-006
  await req.close();
}
