// Clean: an untrusted value is coerced through `int.parse` before it reaches a
// command. Numeric coercion strips every shell metacharacter (and throws on
// non-numeric input), so the value handed to `Process.run` can only ever be a
// number — no injection is possible. A correct scanner emits nothing; any finding
// here is a false positive. nox's `int.parse` sanitizer neutralizes the injection
// classes on the path.
import 'dart:io';

Future<void> runReport() async {
  final raw = Platform.environment['COUNT'] ?? '0';
  final count = int.parse(raw);
  await Process.run('generate-report', ['--count', '$count']);
}
