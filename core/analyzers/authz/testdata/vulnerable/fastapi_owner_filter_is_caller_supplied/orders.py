from fastapi import APIRouter, Depends
from deps import get_current_user, get_db
from models import Order

router = APIRouter(prefix="/orders")


@router.get("/{order_id}")
def read_order(order_id: int, user_id: int, current_user=Depends(get_current_user), db=Depends(get_db)):
    return db.query(Order).filter(Order.id == order_id, Order.user_id == user_id).first()  # expect: AUTHZ-001
