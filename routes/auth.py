from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from auth.google import (
    ATTEMPT_TTL, COOKIE_NAME, COOKIE_PATH, GoogleSettings, OAuthError,
    begin_login, consume_attempt, exchange_identity, resolve_user,
)
from auth.session import (
    COOKIE_NAME as SESSION_COOKIE_NAME, SessionError, SessionSettings,
    create_session, set_session_cookie, user_profile,
)

router = APIRouter(prefix="/auth/google", tags=["Authentication"])


def finish_response(response):
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


@router.get("/login")
def google_login(request: Request):
    try:
        settings = GoogleSettings.from_environment()
        with Session(request.app.state.database_engine) as session:
            location, browser = begin_login(session, settings)
        response = RedirectResponse(location, status_code=302)
        response.set_cookie(
            COOKIE_NAME, browser, max_age=ATTEMPT_TTL, httponly=True,
            secure=settings.secure_cookie, samesite="lax", path=COOKIE_PATH,
        )
    except OAuthError as error:
        response = JSONResponse({"detail": error.detail}, status_code=error.status)
    return finish_response(response)


def complete_google_login(request: Request):
    settings = GoogleSettings.from_environment()
    for key in ("state", "code", "error"):
        if len(request.query_params.getlist(key)) > 1:
            raise OAuthError(400, "Invalid OAuth callback parameters")
    with Session(request.app.state.database_engine) as session:
        nonce, verifier = consume_attempt(
            session, request.query_params.get("state"), request.cookies.get(COOKIE_NAME),
        )
        if error := request.query_params.get("error"):
            raise OAuthError(400, "Google authorization denied" if error == "access_denied" else "Google authorization failed")
        code = request.query_params.get("code")
        if not code or len(code) > 4096:
            raise OAuthError(400, "Missing or invalid authorization code")
        claims = exchange_identity(code, verifier, nonce, settings)
        user = resolve_user(session, claims, settings)
        return user.id, user_profile(user)


@router.get("/callback")
async def google_callback(request: Request):
    try:
        settings = SessionSettings.from_environment()
        if not settings.secure_cookie and request.url.hostname not in {"localhost", "127.0.0.1", "::1"}:
            raise SessionError(503, "Insecure session cookies require a local host")
        user_id, profile = await run_in_threadpool(complete_google_login, request)
        token = await create_session(
            request.app.state.redis_client, user_id, settings, request.cookies.get(SESSION_COOKIE_NAME),
        )
        response = JSONResponse({"user": profile})
        set_session_cookie(response, token, settings)
    except (OAuthError, SessionError) as error:
        response = JSONResponse({"detail": error.detail}, status_code=error.status)
    response.delete_cookie(COOKIE_NAME, path=COOKIE_PATH, httponly=True, samesite="lax")
    return finish_response(response)
