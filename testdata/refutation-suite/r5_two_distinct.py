# Guards: flow identity and structural deduplication (Track F).
#
# Track F merges observations that describe one underlying condition: a source,
# its propagation and its sink are one security hypothesis, not three
# vulnerabilities. TRIAGE-002 is the motivating case — a rule re-reporting, one
# line up, what the taint engine already found.
#
# The failure mode on the other side is merging things that only LOOK like one
# condition. Here a single tainted value reaches two different sinks on
# consecutive lines. They share a source, a variable, and a line neighbourhood
# — every cheap signal a merger would key on — but they are two distinct
# vulnerabilities with different classes and different fixes. Collapsing them
# to one silently drops a real finding, and the count looks like an
# improvement.
import os


def handle(request):
    target = request.args.get("target")
    os.system("ping -c1 " + target)  # nox-expect: TAINT-002
    eval("check(" + target + ")")  # nox-expect: TAINT-005
