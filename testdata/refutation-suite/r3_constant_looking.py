# Guards: constant-argument refutation (Track E2).
#
# Milestone E2 re-expresses the AI-006 fix as evidence: a regex match is
# refuted when every argument to the matched call is deterministically
# constant. That is a sound refutation and a valuable one.
#
# It is only sound if "constant" means constant. Here the sink's argument is a
# concatenation whose left operand is a module-level string constant with an
# innocuous name — and whose right operand is read from the environment. An
# analysis that resolves SAFE_PREFIX, sees a literal, and stops has refuted a
# live command injection on the strength of the half of the expression that
# was never the problem.
import os
import subprocess

SAFE_PREFIX = "echo "


def run_report():
    tail = os.environ["REPORT_TARGET"]
    subprocess.call(SAFE_PREFIX + tail, shell=True)  # nox-expect: TAINT-002
