from fastapi import APIRouter, Depends
from deps import get_db
from models import Product

router = APIRouter(prefix="/products")


@router.get("/{product_id}")
def read_product(product_id: int, db=Depends(get_db)):
    return db.query(Product).filter(Product.id == product_id).first()
