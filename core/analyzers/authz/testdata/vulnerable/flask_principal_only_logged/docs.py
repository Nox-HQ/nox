import logging
from flask import Blueprint, jsonify
from flask_login import login_required, current_user
from .models import Document

log = logging.getLogger(__name__)
bp = Blueprint("docs", __name__, url_prefix="/docs")


@bp.route("/<int:doc_id>")
@login_required
def show(doc_id):
    doc = Document.query.get_or_404(doc_id)  # expect: AUTHZ-001
    log.info("user %s read document %s", current_user.id, doc.id)
    return jsonify(doc.to_dict())
