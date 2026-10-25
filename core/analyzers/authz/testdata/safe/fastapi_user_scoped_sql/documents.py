from fastapi import FastAPI, Depends
from auth import get_current_user
import db

app = FastAPI()


@app.get("/api/v4/documents/{doc_id}")
async def read_doc(doc_id: int, user=Depends(get_current_user)):
    return db.fetch_one("SELECT * FROM documents WHERE id = %s AND owner_id = %s", (doc_id, user.id))
