from flask import request
import sqlite3

def safe_search():
    q = request.args.get("q")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # Parameterized query — not vulnerable.
    cursor.execute("SELECT * FROM items WHERE name=%s", (q,))
    return cursor.fetchall()
