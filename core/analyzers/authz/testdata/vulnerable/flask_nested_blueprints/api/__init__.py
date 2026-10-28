from flask import Blueprint
from .reports import reports_bp

api_bp = Blueprint("api", __name__)
api_bp.register_blueprint(reports_bp, url_prefix="/reports")
