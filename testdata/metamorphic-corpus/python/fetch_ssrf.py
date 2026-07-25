import requests

from flask import Flask, request

app = Flask(__name__)


@app.route("/proxy")
def proxy():
    url = request.args.get("url")
    resp = requests.get(url, timeout=5)
    return resp.text


@app.route("/webhook")
def webhook():
    callback = request.args.get("callback")
    requests.post(callback, json={"event": "ping"}, timeout=5)
    return "sent"
