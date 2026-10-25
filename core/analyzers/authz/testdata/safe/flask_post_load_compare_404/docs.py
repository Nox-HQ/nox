from flask import Blueprint, abort, jsonify
from flask_login import login_required, current_user
from .db import db
from .models import Document

bp = Blueprint("docs", __name__)


@bp.route("/docs/<int:doc_id>")
@login_required
def get_doc(doc_id):
    doc = db.session.get(Document, doc_id)
    if doc is None or doc.user_id != current_user.id:
        abort(404)
    return jsonify(doc.to_dict())
