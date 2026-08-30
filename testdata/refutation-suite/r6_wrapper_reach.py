# Guards: reachability (Track G).
#
# Gate B is the rule that deterministic unreachability may suppress a finding
# and unknown reachability may not. This sample is the shape that makes a naive
# reachability check answer "unreachable" with confidence.
#
# The dangerous sink is never called with untrusted input directly. It sits
# behind a private one-line wrapper, and the tainted value crosses the function
# boundary as an argument. An analysis that asks "does a source flow into a
# sink in this function?" finds nothing in either function and concludes the
# code is safe. The vulnerability is fully reachable; only the analysis was
# intraprocedural.
import os


def _exec(argument):
    os.system(argument)


def handle(request):
    host = request.args.get("host")
    _exec("ping -c1 " + host)  # nox-expect: TAINT-002
