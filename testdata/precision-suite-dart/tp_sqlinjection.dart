// SQL injection: a user-controlled value is string-interpolated straight into a
// SQL string and handed to sqflite's `db.rawQuery` with no `?` placeholder and no
// bound arguments. This is CWE-89. A correct scanner fires TAINT-001. nox's Dart
// taint model sees the tainted value reach the `$id` interpolation (CODE, per
// lexctx) that builds the query string and then the rawQuery sink, with no
// parameterized-query form on the path (rawQuery is only safe with a `?`
// placeholder SQL string and an args list).
import 'dart:io';
import 'package:sqflite/sqflite.dart';

Future<void> lookupUser(Database db) async {
  final id = Platform.environment['USER_ID'] ?? '';
  final sql = 'SELECT * FROM users WHERE id = $id';
  await db.rawQuery(sql); // nox-expect: TAINT-001
}
