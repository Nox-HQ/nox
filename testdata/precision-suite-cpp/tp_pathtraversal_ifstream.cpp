// Path traversal (C++): a user-controlled path from the environment is opened
// with std::ifstream with no canonicalization, so `../` traversal escapes the
// intended directory. This is CWE-22. A correct scanner fires TAINT-004; nox
// normalizes std::ifstream to std.ifstream and suffix-matches the `ifstream`
// catalog key.
#include <cstdlib>
#include <fstream>
#include <string>

std::string read_config(void) {
    std::string path = std::getenv("CONFIG");
    std::ifstream in(path); // nox-expect: TAINT-004
    std::string data;
    in >> data;
    return data;
}
