from flask import Flask, abort, jsonify
from flask_login import current_user
from models import Order

app = Flask(__name__)


@app.before_request
def require_login():
    if not current_user.is_authenticated:
        abort(401)


@app.route("/orders/<int:order_id>")
def get_order(order_id):
    return jsonify(Order.query.get_or_404(order_id).to_dict())  # expect: AUTHZ-001
