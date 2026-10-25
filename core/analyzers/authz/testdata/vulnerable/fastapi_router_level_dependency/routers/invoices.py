from fastapi import APIRouter, Depends
from sqlalchemy import select
from deps import get_current_user, get_session
from models import Invoice

router = APIRouter(prefix="/invoices", dependencies=[Depends(get_current_user)])


@router.get("/{invoice_id}")
def read_invoice(invoice_id: int, session=Depends(get_session)):
    stmt = select(Invoice).where(Invoice.id == invoice_id)  # expect: AUTHZ-001
    return session.execute(stmt).scalar_one()
