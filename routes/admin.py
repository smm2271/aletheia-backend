from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from auth.admin import require_admin
from models import User

router = APIRouter(prefix="/api/v1/admin", tags=["Administration"])


@router.get("/me")
async def admin_status(user: User = Depends(require_admin)):
    return JSONResponse({"user_id": str(user.id), "is_admin": True}, headers={"Cache-Control": "no-store"})
