from flask import Flask, jsonify
from flask_login import login_required
import db
from session_store import resolve_uid

app = Flask(__name__)


@app.route("/orders/<int:order_id>")
@login_required
def get_order(order_id):
    uid = resolve_uid()
    row = db.query("SELECT * FROM orders WHERE id = %s AND user_id = %s", (order_id, uid))
    return jsonify(row)
