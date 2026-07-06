// Command injection: an attacker-controlled value (an environment variable
// standing in for any untrusted input) is string-interpolated into a shell
// command and handed to `Process.run` with `runInShell: true`, so /bin/sh -c
// executes the interpolated string. This is CWE-78. A correct scanner fires
// TAINT-002. nox's Dart taint model sees the tainted value reach the `$name`
// interpolation (which lexctx classifies as CODE) and then the `Process.run`
// sink with no allow-list.
import 'dart:io';

Future<void> runReport() async {
  final name = Platform.environment['REPORT'] ?? '';
  await Process.run('sh', ['-c', 'generate-report $name'], runInShell: true); // nox-expect: TAINT-002
}
