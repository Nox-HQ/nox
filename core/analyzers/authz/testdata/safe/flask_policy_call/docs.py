from flask import Blueprint, jsonify
from flask_login import login_required
from .models import Document
from .policy import check_policy

bp = Blueprint("docs", __name__, url_prefix="/docs")


@bp.route("/<int:doc_id>")
@login_required
def show(doc_id):
    doc = Document.query.get_or_404(doc_id)
    check_policy(doc, "read")
    return jsonify(doc.to_dict())
