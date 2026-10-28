from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session
from ..deps import SessionDep, get_current_user
from ..models import Item

router = APIRouter(prefix="/items", tags=["items"])


@router.get("/{id}")
def read_item(session: SessionDep, current_user: Annotated[str, Depends(get_current_user)], id: int):
    item = session.get(Item, id)  # expect: AUTHZ-001
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    return item
