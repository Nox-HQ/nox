# Clean sample: every exec below passes the tainted value as a separate ARGV
# element, so no shell interprets it. Any finding here is a FALSE POSITIVE.
#
# A real taint SOURCE is required for this to test anything. clean_safe_db.py
# takes `user_input` as a function parameter, so nothing flows into its
# subprocess calls and it stays clean whether the arg-vector exemption works or
# not — it cannot detect a regression in the thing it appears to guard.
# sys.argv is a source, so these lines are genuinely reachable taint.
#
# check_output was missing from the arg-vector exemption that run/call/Popen
# have, so it reported a command injection where the identical subprocess.run
# call did not. Found on httpie, where it was the repository's only taint
# finding and was not an injection.
import subprocess
import sys


def run():
    user = sys.argv[1]
    subprocess.check_output(["git", "log", user])
    subprocess.run(["ls", "-la", user])
    subprocess.call(["echo", user])
    subprocess.Popen(["cat", user])
