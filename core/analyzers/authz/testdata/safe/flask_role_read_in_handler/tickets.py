from flask import Blueprint, jsonify
from flask_login import login_required, current_user
from .models import Ticket

bp = Blueprint("tickets", __name__, url_prefix="/tickets")


@bp.route("/<int:ticket_id>")
@login_required
def show(ticket_id):
    ticket = Ticket.query.get_or_404(ticket_id)
    if current_user.role != "support":
        return jsonify(error="not found"), 404
    return jsonify(ticket.to_dict())
