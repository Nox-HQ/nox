from flask import Flask, jsonify
from flask_login import login_required, current_user
from models import Order

app = Flask(__name__)


@app.route("/orders/<int:order_id>")
@login_required
def get_order(order_id):
    order = Order.query.filter_by(id=order_id, user_id=current_user.id).first_or_404()
    return jsonify(order.to_dict())
