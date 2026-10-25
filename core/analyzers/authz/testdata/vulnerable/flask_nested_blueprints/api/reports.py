from flask import Blueprint, jsonify
from flask_login import login_required
from models import Report

reports_bp = Blueprint("reports", __name__)


@reports_bp.route("/<int:report_id>")
@login_required
def show(report_id):
    return jsonify(Report.query.get(report_id).to_dict())  # expect: AUTHZ-001
