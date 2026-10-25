from fastapi import APIRouter, Depends
from api.deps import get_current_user, SessionDep
from models import Order

router = APIRouter(prefix="/orders", tags=["orders"])


@router.get("/{order_id}")
def read_order(session: SessionDep, user=Depends(get_current_user), order_id: int = 0):
    return session.get(Order, order_id)  # expect: AUTHZ-001
