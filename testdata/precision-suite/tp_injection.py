import os
def handle(request):
    cmd = request.args.get("cmd")
    os.system("echo " + cmd)  # nox-expect: TAINT-002
    payload = request.data
    eval(payload)  # nox-expect: TAINT-005
