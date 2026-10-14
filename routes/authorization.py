from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from starlette.concurrency import run_in_threadpool

from auth.session import SessionError, SessionSettings, get_current_user
from sso.authorization import (
    CONTEXT_COOKIE, CONTEXT_TTL, callback_uri, consent_required, consume_context,
    issue_code, parse_request, store_context, validate_request,
)

router = APIRouter(tags=["Authorization"])


def finish(response):
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


async def grant(request, params, client, user):
    if consent_required(client):
        return finish(JSONResponse({"detail": "Consent required", "policy": "consent_required", "client_id": client.client_id, "scope": params.scopes}, status_code=403))
    code = await issue_code(request.app.state.redis_client, user.id, params)
    return finish(RedirectResponse(callback_uri(params, code), status_code=302))


@router.get("/authorize")
async def authorize(request: Request):
    params = parse_request(request.query_params)
    client = await run_in_threadpool(validate_request, request.app.state.database_engine, params)
    try:
        user = await get_current_user(request)
    except SessionError as error:
        if error.status != 401:
            raise
        settings = SessionSettings.from_environment()
        if not settings.secure_cookie and request.url.hostname not in {"localhost", "127.0.0.1", "::1"}:
            raise SessionError(503, "Insecure continuation cookies require a local host")
        token = await store_context(request.app.state.redis_client, params)
        response = RedirectResponse("/auth/google/login?continue=authorization", status_code=302)
        response.set_cookie(CONTEXT_COOKIE, token, max_age=CONTEXT_TTL, httponly=True, secure=settings.secure_cookie, samesite="lax", path="/")
        return finish(response)
    return await grant(request, params, client, user)


@router.get("/authorize/resume")
async def resume_authorization(request: Request):
    user = await get_current_user(request)
    try:
        params = await consume_context(request.app.state.redis_client, request.cookies.get(CONTEXT_COOKIE))
        client = await run_in_threadpool(validate_request, request.app.state.database_engine, params)
        response = await grant(request, params, client, user)
    except HTTPException as error:
        response = JSONResponse({"detail": error.detail}, status_code=error.status_code)
    response.delete_cookie(CONTEXT_COOKIE, path="/", httponly=True, secure=SessionSettings.from_environment().secure_cookie, samesite="lax")
    return finish(response)
