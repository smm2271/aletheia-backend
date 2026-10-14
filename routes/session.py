from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, Response

from auth.session import (
    COOKIE_NAME, SessionError, SessionSettings, clear_session_cookie,
    get_current_user, revoke_session, user_profile,
)
from models import User

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.get("/me")
async def current_user(user: User = Depends(get_current_user)):
    return JSONResponse({"user": user_profile(user)}, headers={"Cache-Control": "no-store"})


@router.post("/logout", status_code=204)
async def logout(request: Request):
    settings = SessionSettings.from_environment()
    if request.headers.get("origin") != settings.public_origin:
        raise SessionError(403, "Invalid request origin")
    await revoke_session(request.app.state.redis_client, request.cookies.get(COOKIE_NAME))
    response = Response(status_code=204, headers={"Cache-Control": "no-store"})
    clear_session_cookie(response)
    return response
