from flask import Blueprint, jsonify
from flask_login import login_required
from .decorators import roles_required
from .models import User

bp = Blueprint("admin", __name__, url_prefix="/admin")


@bp.route("/users/<int:user_id>")
@login_required
@roles_required("admin")
def show_user(user_id):
    return jsonify(User.query.get_or_404(user_id).to_dict())
