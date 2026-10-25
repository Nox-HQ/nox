from typing import Annotated
from fastapi import Depends
from sqlmodel import Session

SessionDep = Annotated[Session, Depends(get_db)]
CurrentUser = Annotated[User, Depends(get_current_user)]
