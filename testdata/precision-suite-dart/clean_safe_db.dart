// Clean: a parameterized sqflite query. The untrusted value is passed as a bound
// argument in the args list (2nd positional) with a `?` placeholder in the SQL
// string (1st positional), so it never becomes part of the SQL text. A correct
// scanner emits nothing; any finding here is a false positive. nox's argument-
// shape check recognizes the placeholder form (ArgCount >= 2, taint not in the
// first argument) and suppresses it.
import 'dart:io';
import 'package:sqflite/sqflite.dart';

Future<void> lookupUser(Database db) async {
  final id = Platform.environment['USER_ID'] ?? '';
  await db.rawQuery('SELECT * FROM users WHERE id = ?', [id]);
}
