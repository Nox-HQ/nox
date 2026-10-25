from flask import Blueprint, abort, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from .models import Document

bp = Blueprint("docs", __name__, url_prefix="/docs")


@bp.get("/<int:doc_id>")
@jwt_required()
def get_doc(doc_id):
    doc = Document.query.get_or_404(doc_id)
    if doc.owner_id != get_jwt_identity():
        abort(403)
    return jsonify(doc.to_dict())
