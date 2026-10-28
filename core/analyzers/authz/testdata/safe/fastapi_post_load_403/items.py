from fastapi import APIRouter, HTTPException
from deps import SessionDep, CurrentUser
from models import Item

router = APIRouter(prefix="/items")


@router.get("/{id}")
def read_item(session: SessionDep, current_user: CurrentUser, id: int):
    item = session.get(Item, id)
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    if item.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not enough permissions")
    return item
