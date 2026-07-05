# Path traversal: an untrusted request parameter flows into open() unchecked.
def read_file(request):
    user_path = request.args.get("path")
    with open(user_path) as f:  # nox-expect: TAINT-004
        return f.read()
