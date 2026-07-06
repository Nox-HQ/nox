// Clean: parameterized SQL via sqlite3 bind parameters. The user-controlled value
// is bound with sqlite3_bind_text against a `?` placeholder — sent to the driver
// as data, never concatenated into the query string — so there is NO SQL
// injection here. A correct scanner emits nothing; any TAINT-001 finding on this
// file is a false positive.
#import <Foundation/Foundation.h>
#import <sqlite3.h>

void lookupUserSafe(sqlite3 *db) {
    NSString *uid = [[NSUserDefaults standardUserDefaults] stringForKey:@"uid"];
    sqlite3_stmt *stmt;
    // Static SQL with a placeholder; the value is bound, not interpolated.
    sqlite3_prepare_v2(db, "SELECT * FROM users WHERE id = ?", -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, [uid UTF8String], -1, NULL);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}
