from fastapi import FastAPI
from routers import invoices

app = FastAPI()
app.include_router(invoices.router)
