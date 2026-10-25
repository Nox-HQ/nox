from flask import Blueprint, abort, jsonify
from flask_login import login_required
from .models import Document

bp = Blueprint("docs", __name__, url_prefix="/docs")


@bp.route("/<int:doc_id>")
@login_required
def show(doc_id):
    doc = Document.query.get_or_404(doc_id)
    if not doc.is_shared:
        abort(403)
    return jsonify(doc.to_dict())
