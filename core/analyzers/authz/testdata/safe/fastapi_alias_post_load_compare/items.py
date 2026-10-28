from fastapi import APIRouter, HTTPException
from deps import CurrentUser, SessionDep
from models import Item

router = APIRouter(prefix="/items")


@router.get("/{id}")
def read_item(session: SessionDep, current_user: CurrentUser, id: int):
    item = session.get(Item, id)
    if item is None or item.owner_id != current_user.id:
        raise HTTPException(status_code=404)
    return item
