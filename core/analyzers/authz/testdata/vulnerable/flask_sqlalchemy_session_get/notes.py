from flask import Blueprint, jsonify, request
from flask_login import login_required
from .db import db
from .models import Note

notes = Blueprint("notes", __name__, url_prefix="/notes")


@notes.route("/<uuid:note_id>", methods=["DELETE"])
@login_required
def delete_note(note_id):
    note = db.session.get(Note, note_id)  # expect: AUTHZ-001
    db.session.delete(note)
    db.session.commit()
    return "", 204
