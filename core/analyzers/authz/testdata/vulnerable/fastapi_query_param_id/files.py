from fastapi import APIRouter, Depends
from deps import get_current_user
import db

router = APIRouter(prefix="/files")


@router.get("/")
async def read_file(file_id: int, user=Depends(get_current_user)):
    return await db.fetch_one("SELECT * FROM files WHERE id = :id", {"id": file_id})  # expect: AUTHZ-001
