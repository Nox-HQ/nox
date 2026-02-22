from flask import request
import os

def run_command():
    cmd = request.form["cmd"]
    os.system(cmd)
