// SSRF: an attacker-controlled URL string is turned into a Uri and fetched by
// package:http's `get` with no host allow-list, so the server can be coerced into
// requesting an internal address. This is CWE-918. A correct scanner fires
// TAINT-006. nox's Dart taint model matches the tainted URL flowing into the
// http.get sink with no allow-list on the path.
import 'dart:io';
import 'package:http/http.dart' as http;

Future<String> fetch() async {
  final raw = Platform.environment['TARGET'] ?? '';
  final resp = await http.get(Uri.parse(raw)); // nox-expect: TAINT-006
  return resp.body;
}
