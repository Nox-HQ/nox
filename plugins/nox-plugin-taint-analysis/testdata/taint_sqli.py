from flask import request
import sqlite3

def search():
    q = request.args.get("q")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM items WHERE name='" + q + "'")
    return cursor.fetchall()
