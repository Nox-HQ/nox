// Clean: a C++11 raw string holds an embedded base64 data-URI blob (an icon) and
// a long placeholder token. lexctx classifies the raw-string body as a data blob,
// so a 32+ char token inside it is never mistaken for a hardcoded secret, and no
// taint sink operates on the blob. A correct scanner emits nothing; a finding
// here would be a false positive from matching pattern-shaped bytes inside data.
#include <string>

// A generated asset embedded verbatim as a raw string. The `//` and base64 runs
// inside must not be lexed as code/comment/secret.
static const std::string kIcon = R"(data:image/svg+xml;base64,PHN2ZyB4bWx)"
    R"(ucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIxNiI+PHBhdGggZD0i)"
    R"(TTAgMGgxNnYxNkgweiIvPjwvc3ZnPkFLSUExMjM0NTY3ODkwQUJDREVGMTIzNDU2Nzg5)";

std::string icon() {
    return kIcon;
}
