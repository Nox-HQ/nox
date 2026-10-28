from fastapi import APIRouter, Depends
from sqlalchemy import select
from deps import get_current_user, get_session
from models import Invoice

router = APIRouter(prefix="/invoices")


@router.get("/{invoice_id}")
def read_invoice(invoice_id: int, user=Depends(get_current_user), session=Depends(get_session)):
    stmt = select(Invoice).where(Invoice.id == invoice_id, Invoice.owner_id == user.id)
    return session.execute(stmt).scalar_one()
