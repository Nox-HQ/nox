// Clean: placeholder credentials and a fixed banner. The strings look
// secret-shaped but are obvious placeholders in ordinary string literals, and no
// untrusted input reaches any sink. A correct scanner emits nothing; a taint
// finding here would be a false positive.
#include <stdio.h>

#define DB_USER "REPLACE_ME_USER"
#define DB_PASS "CHANGE_ME_BEFORE_DEPLOY"
#define API_KEY "your-api-key-here-000000000000"

// A generated build banner, printed with a fixed format.
static const char *kBanner =
    "app v1.0.0 (build 00000000) - configure credentials in /etc/app/secrets";

void print_banner(void) {
    printf("%s\n", kBanner);
}
