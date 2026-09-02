# True positives for the ordinary Python import idioms.
#
# The corpus tested only `import os` + `os.system(...)` — the ONE shape where
# the local name happens to equal the module name, which is the shape the
# catalog matched. `from os import system` and `import os as o` are how Python
# is normally written, and both were silently missed: the same flow, reported
# only when the import was written the unusual way.
#
# The suite scoring 1.00 recall while the engine missed the common idiom is why
# these samples exist. If a future change drops import resolution, recall here
# falls and says so.
#
# `request` arrives as a parameter, as in tp_injection.py, so the sample tests
# the import idiom of the SINK and nothing else.
from os import system
import os as operating_system
import subprocess as sp


def from_import(request):
    cmd = request.args.get("cmd")
    system("echo " + cmd)  # nox-expect: TAINT-002


def aliased_module(request):
    cmd = request.args.get("cmd")
    operating_system.system("echo " + cmd)  # nox-expect: TAINT-002


def aliased_package(request):
    cmd = request.args.get("cmd")
    sp.check_output("echo " + cmd, shell=True)  # nox-expect: TAINT-002
