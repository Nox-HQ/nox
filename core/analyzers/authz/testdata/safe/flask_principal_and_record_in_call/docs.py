from flask import Blueprint, jsonify
from flask_login import login_required, current_user
from .models import Document
from .views import visible_fields

bp = Blueprint("docs", __name__, url_prefix="/docs")


@bp.route("/<int:doc_id>")
@login_required
def show(doc_id):
    doc = Document.query.get_or_404(doc_id)
    return jsonify(visible_fields(doc, current_user))
