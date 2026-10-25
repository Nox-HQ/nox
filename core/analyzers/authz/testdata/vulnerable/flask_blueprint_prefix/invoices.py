from flask import Blueprint, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from .models import Invoice

bp = Blueprint("invoices", __name__)


@bp.get("/<invoice_id>")
@jwt_required()
def read_invoice(invoice_id):
    invoice = Invoice.query.get_or_404(invoice_id)  # expect: AUTHZ-001
    return jsonify(invoice.to_dict())
