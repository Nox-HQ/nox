from flask import Flask, jsonify
from flask_login import login_required, current_user
import db

app = Flask(__name__)


@app.route("/orders/<int:order_id>")
@login_required
def get_order(order_id):
    row = db.query("SELECT * FROM orders WHERE id = %s AND user_id = %s", (order_id, current_user.id))
    return jsonify(row)
