from flask import Flask, jsonify
from flask_login import login_required, current_user

app = Flask(__name__)


@app.route("/orders/<int:order_id>")
@login_required
def get_order(order_id):
    order = current_user.orders.filter_by(id=order_id).first_or_404()
    return jsonify(order.to_dict())
