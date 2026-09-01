# Safe database and command idioms — every one is the correct, guarded form, so
# a precise scanner fires nothing. Zero findings expected.
#
# The values come from sys.argv, a real taint SOURCE. That is load-bearing:
# this file previously took `user_input` as a function PARAMETER, so nothing
# flowed into these calls and the sample stayed clean whether the arg-vector and
# parameterized-query refinements worked, broke, or were deleted. A clean sample
# with no source proves nothing — it reads like a guard and is inert.
import subprocess, shlex, sys


def run(db):
    user_input = sys.argv[1]
    subprocess.run(["ls", "-la", user_input])          # arg vector, not a shell
    db.execute("SELECT * FROM t WHERE id = %s", (user_input,))  # parameterized
    subprocess.run("grep " + shlex.quote(user_input), shell=True)  # quoted
