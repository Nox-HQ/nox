from typing import Annotated
from fastapi import Depends

CurrentUser = Annotated[dict, Depends(get_current_user)]
