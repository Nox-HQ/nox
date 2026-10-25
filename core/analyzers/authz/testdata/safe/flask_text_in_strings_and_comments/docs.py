from flask import Flask, jsonify
from flask_login import login_required

app = Flask(__name__)

# @app.route("/old/<int:doc_id>") then Document.query.get_or_404(doc_id)
NOTE = """
@app.route("/docs/<int:doc_id>")
@login_required
def get_doc(doc_id):
    return Document.query.get_or_404(doc_id)
"""


@app.route("/health")
@login_required
def health():
    return jsonify(ok=True)
