from flask import Blueprint, jsonify
from flask_login import login_required, current_user
from . import db
from .models import Ticket

bp = Blueprint("tickets", __name__, url_prefix="/tickets")


@bp.route("/<int:ticket_id>")
@login_required
def show(ticket_id):
    ticket = (
        db.session.query(Ticket)
        .filter(Ticket.id == ticket_id)
        .filter(Ticket.owner_id == current_user.id)
        .first_or_404()
    )
    return jsonify(ticket.to_dict())
