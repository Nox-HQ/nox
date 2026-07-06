// SQL injection: an attacker-controlled id is string-formatted directly into a
// SQL statement and executed by sqlite3_exec, which runs the raw SQL text. This
// is CWE-89. A correct scanner fires TAINT-001. The safe form binds the value
// with sqlite3_bind against a `?` placeholder (see clean_safe_db.m). nox sees the
// tainted value reach the query string and then the sqlite3_exec sink.
#import <Foundation/Foundation.h>
#import <sqlite3.h>

void lookupUser(sqlite3 *db) {
    NSString *uid = [[NSUserDefaults standardUserDefaults] stringForKey:@"uid"];
    NSString *sql = [NSString stringWithFormat:@"SELECT * FROM users WHERE id = '%@'", uid];
    sqlite3_exec(db, [sql UTF8String], NULL, NULL, NULL); // nox-expect: TAINT-001
}
