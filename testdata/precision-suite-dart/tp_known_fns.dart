// Honest FALSE NEGATIVES for Dart. Both are real flows a correct scanner
// reports, and both are the Dart side of a capability the engine HAS but scopes
// per language: receiver taint and container binding are enabled only where a
// corpus demanded them, because each is an over-approximation that can only
// widen taint. Dart has not opted in, so these miss.
//
// They replace tp_ssrf_field.dart, which was withdrawn: its comment described a
// tainted URL stored into `req.url` and fetched by `client.send(req)`, but its
// code used a CONSTANT URL and put the tainted value in a request HEADER, so the
// annotated CWE-918 did not hold for the code as written. Its premise is also
// not realizable in Dart — `HttpClientRequest` exposes no settable URL field,
// and across 1213 real Dart files there is not one `request.url = ...`
// assignment. Correct SSRF coverage lives in tp_ssrf.dart.
import 'dart:io';

// FN: cross-method flow through an INSTANCE FIELD. The source lands in `target`
// in one method and the sink reads it in another. The engine joins shared state
// across units for Ruby (@ivar) and Perl (`our`), but Dart is not in that set,
// so the two methods are analyzed independently and the flow is not joined.
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

// FN: taint laundered through a LIST ELEMENT. Binding a container from an
// element assignment is enabled for Perl only, so the store is not tracked and
// the later read of the element looks clean.
Future<void> fetchFirst(HttpClient client) async {
  final urls = <String>[];
  urls.add(Platform.environment['TARGET'] ?? '');
  final req = await client.getUrl(Uri.parse(urls[0])); // nox-expect: TAINT-006
  await req.close();
}
