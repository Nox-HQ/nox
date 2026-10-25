from fastapi import APIRouter
from api.routes import orders

api_router = APIRouter()
api_router.include_router(orders.router)
