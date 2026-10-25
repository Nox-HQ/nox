from flask import Flask, request, jsonify
from flask_login import login_required
from models import Document

app = Flask(__name__)


@app.post("/documents/share")
@login_required
def share_document():
    data = request.get_json()
    doc = Document.query.filter_by(id=data["document_id"]).first()  # expect: AUTHZ-001
    return jsonify(doc.to_dict())
