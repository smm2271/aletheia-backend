from fastapi import Depends

from auth.session import SessionError, get_current_user
from models import User


async def require_admin(user: User = Depends(get_current_user)) -> User:
    if not user.is_admin:
        raise SessionError(403, "Administrator access required")
    return user
