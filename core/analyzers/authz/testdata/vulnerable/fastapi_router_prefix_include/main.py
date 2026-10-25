from fastapi import FastAPI
from .routers import items

app = FastAPI()
app.include_router(items.router, prefix="/api/v1")
