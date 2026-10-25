from flask import Flask, jsonify
from models import Product

app = Flask(__name__)


@app.route("/products/<int:product_id>")
def get_product(product_id):
    product = Product.query.get_or_404(product_id)
    return jsonify(product.to_dict())
