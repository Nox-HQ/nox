import os
import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/ping")
def ping():
    host = request.args.get("host")
    os.system("ping -c 1 " + host)
    return "ok"


@app.route("/backup")
def backup():
    target = request.args.get("path")
    subprocess.call("tar czf backup.tgz " + target, shell=True)
    return "queued"
