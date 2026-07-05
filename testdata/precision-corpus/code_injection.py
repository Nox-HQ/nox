# True-positive sample: untrusted input flowing into a code-execution
# sink. Passing user_input to eval() is a command/code-injection class
# bug (CWE-95). The scan MUST flag the eval call below.


def dispatch(user_input):
    handler = eval("handlers.do_" + user_input)  # nox-expect: AI-049
    return handler
