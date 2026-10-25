from fastapi import APIRouter, Depends
from deps import get_current_active_superuser, get_db
from models import User

router = APIRouter(prefix="/users")


@router.get("/{user_id}", dependencies=[Depends(get_current_active_superuser)])
def read_user(user_id: int, db=Depends(get_db)):
    return db.query(User).filter(User.id == user_id).first()
