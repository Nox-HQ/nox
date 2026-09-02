# Clean: the sanitizer sits on the SAME line as the source it validates —
# `n = int(request.args.get('n'))` — the ordinary way input is coerced. The
# engine used to bind n from the source with nothing cleared, so every such
# validated value fired at its sink; only the two-step idiom in
# clean_safe_db.py (bind raw, then coerce) was clean. A finding on any line
# here is a false positive.
import os
import shlex
import subprocess


def sleep_for(request):
    n = int(request.args.get("n"))
    os.system("sleep " + str(n))          # coerced to a number: no metacharacters survive


def grep_for(request):
    pattern = shlex.quote(request.args.get("q"))
    subprocess.run("grep " + pattern, shell=True)   # quoted before it is bound


def page_size(request):
    size = float(request.form.get("size"))
    subprocess.call("head -n " + str(size), shell=True)
