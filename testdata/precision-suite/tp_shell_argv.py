# True positives: the program IS a shell, so the argv vector is not a shield.
#
# The arg-vector exemption exists because a tainted value passed as its own argv
# element is never parsed by a shell — subprocess.run(["ls", user]) is safe. But
# `run(["sh", "-c", cmd])` runs a shell AS the program, which is the ordinary way
# a command line is executed through an argv-taking API, and the exemption
# silenced it. Measured before the fix: five of six such injections across
# subprocess.* and child_process.spawn produced nothing.
#
# clean_argv_exec.py is the other half — the same sinks with a real program,
# which must stay clean. Together they pin the exemption from both sides.
import subprocess
import sys


def run():
    cmd = sys.argv[1]
    subprocess.run(["sh", "-c", "git log " + cmd])  # nox-expect: TAINT-002
    subprocess.check_output(["/bin/bash", "-c", "git log " + cmd])  # nox-expect: TAINT-002
