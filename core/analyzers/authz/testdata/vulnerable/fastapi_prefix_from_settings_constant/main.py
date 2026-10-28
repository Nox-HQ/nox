from fastapi import FastAPI
from api.main import api_router
from core.config import settings

app = FastAPI()
app.include_router(api_router, prefix=settings.API_V1_STR)
