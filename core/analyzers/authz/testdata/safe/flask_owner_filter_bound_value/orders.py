from flask import Flask, jsonify
from flask_login import login_required
from models import Order
from session_store import resolve_uid

app = Flask(__name__)


@app.route("/orders/<int:order_id>")
@login_required
def get_order(order_id):
    uid = resolve_uid()
    order = Order.query.filter_by(id=order_id, user_id=uid).first_or_404()
    return jsonify(order.to_dict())
