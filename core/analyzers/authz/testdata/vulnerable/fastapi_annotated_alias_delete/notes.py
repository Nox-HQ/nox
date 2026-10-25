from typing import Annotated
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from deps import get_current_user, get_db
from models import Note

router = APIRouter()
CurrentUser = Annotated[dict, Depends(get_current_user)]


@router.delete("/notes/{note_id}")
def delete_note(note_id: int, user: CurrentUser, db: Session = Depends(get_db)):
    note = db.query(Note).filter(Note.id == note_id).first()  # expect: AUTHZ-001
    db.delete(note)
    db.commit()
    return {"ok": True}
