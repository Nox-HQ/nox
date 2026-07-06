// Path traversal: an attacker-controlled path is passed to `File(path)` and read
// with `readAsString` with no canonicalization or allow-base check, so
// `../../etc/passwd` escapes the intended directory. This is CWE-22. A correct
// scanner fires TAINT-004. nox's Dart taint model tracks the tainted path into
// the `readAsString` file-read sink; the safe form validates the basename against
// an allow-base first.
import 'dart:io';

Future<String> readConfig() async {
  final path = Platform.environment['CONFIG'] ?? '';
  final contents = await File(path).readAsString(); // nox-expect: TAINT-004
  return contents;
}
