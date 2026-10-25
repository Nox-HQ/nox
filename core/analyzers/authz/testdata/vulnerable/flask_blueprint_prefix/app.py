from flask import Flask
from .invoices import bp as invoices_bp

app = Flask(__name__)
app.register_blueprint(invoices_bp, url_prefix="/api/invoices")
