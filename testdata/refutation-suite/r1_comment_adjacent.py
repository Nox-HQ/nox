# Guards: lexical-context refinement (Track E1).
#
# nox already drops rule matches that land inside comments — core/lexctx
# classifies comment and string regions, and secrets/srccontext.go uses it to
# discard config-field matches found in prose. That refinement is correct and
# must keep working. What must NOT happen is a refiner that decides a file, a
# line, or a region is "prose" and takes real code down with it.
#
# This sample puts both cases next to each other: a genuine sink quoted inside
# a comment (which must stay silent), and a real command injection a few lines
# below whose sink argument is built from a string literal that CONTAINS a
# comment character. A lexer that starts a comment at the first bare '#' it
# sees, rather than tracking string state, would swallow the vulnerable call.
import os


def render_help():
    # os.system("echo safe") is quoted here as prose and must not fire.
    return "usage: tool --cmd <command>"


def handle(request):
    marker = "#"
    cmd = request.args.get("cmd")
    os.system("echo " + marker + cmd)  # nox-expect: TAINT-002
