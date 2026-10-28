from flask import Flask, request, jsonify
from flask_jwt_extended import jwt_required
from models import Project

app = Flask(__name__)


@app.route("/projects")
@jwt_required()
def project():
    pid = request.args.get("project_id")
    return jsonify(Project.query.get_or_404(pid).to_dict())  # expect: AUTHZ-001
