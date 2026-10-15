from fastapi import APIRouter, Body, Depends, HTTPException, Request, Response
from fastapi.security import APIKeyCookie
from pydantic import BaseModel, ConfigDict
from sqlalchemy.exc import SQLAlchemyError
from starlette.concurrency import run_in_threadpool

from auth.session import COOKIE_NAME, get_current_user, require_same_origin
from models import User
from qr.credentials import CredentialResponse, get_or_issue

router = APIRouter(tags=["Static QR credentials"])


class CredentialRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CredentialError(BaseModel):
    detail: str


async def credential_user(request: Request) -> User:
    # Dependency failures occur before the endpoint body, so handle store errors here too.
    try:
        return await get_current_user(request)
    except SQLAlchemyError:
        raise HTTPException(503, "Credential store unavailable", headers={"Cache-Control": "no-store"}) from None
    except HTTPException as error:
        error.headers = {**(error.headers or {}), "Cache-Control": "no-store"}
        raise


@router.post("/api/v1/qr/credentials", response_model=CredentialResponse,
             summary="Obtain the current browser user's static QR credential",
             description=("Requires a browser session and the exact configured Origin. Omit the body or send {}. "
                          "No query parameters or subject selection are accepted. Returns the same signed token "
                          "until expiry, including across signing-key rotation; expires_at is authoritative. "
                          "This endpoint does not validate entry eligibility or authorize admission. "
                          "In Swagger, log in through /auth/google/login in the same browser first; browser JavaScript "
                          "cannot set a Cookie header using Authorize. Serve /docs from SESSION_PUBLIC_ORIGIN so the "
                          "browser sends the session cookie and matching Origin. Examples are synthetic, not usable credentials."),
             dependencies=[Depends(APIKeyCookie(name=COOKIE_NAME, auto_error=False))],
             responses={
                 200: {"description": "Current user's reusable credential; no-store. Example token is a placeholder.",
                       "content": {"application/json": {"example": {
                           "token": "<signed-static-qr-jwt>", "credential_id": "A" * 43, "format_version": 1,
                           "issued_at": "2026-10-15T00:00:00Z", "expires_at": "2026-10-15T00:10:00Z"}}}},
                 **{code: {"model": CredentialError, "description": description,
                           "content": {"application/json": {"example": {"detail": detail}}}}
                    for code, description, detail in (
                        (400, "Query parameters are unsupported", "Only the current browser user may obtain a credential"),
                        (401, "Browser session missing/expired or user deleted/disabled", "Unauthenticated"),
                        (403, "Origin missing or does not exactly match SESSION_PUBLIC_ORIGIN", "Invalid request origin"),
                        (409, "Existing credential unavailable until expiry", "Current QR credential is unavailable; retry after its expiry"),
                        (503, "QR configuration, keys, session store or database unavailable", "Credential store unavailable"))}},
             openapi_extra={
                 "parameters": [{"in": "header", "name": "Origin", "required": True,
                                 "description": "Exact SESSION_PUBLIC_ORIGIN; browsers set this automatically for POST.",
                                 "schema": {"type": "string"}, "example": "http://localhost:8000"}],
                 "responses": {"422": {"description": "Invalid body, including extra properties. FastAPI validation-error schema.",
                                         "content": {"application/json": {"example": {"detail": [
                                             {"type": "extra_forbidden", "loc": ["body", "user_id"],
                                              "msg": "Extra inputs are not permitted", "input": "example"}]}}}}}})
async def issue_credential(request: Request, response: Response,
                           body: CredentialRequest | None = Body(default=None, openapi_examples={
                               "self": {"summary": "Current browser user (body can also be omitted)", "value": {}}}),
                           user: User = Depends(credential_user)):
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    try:
        require_same_origin(request)
        if request.query_params:
            raise HTTPException(400, "Only the current browser user may obtain a credential")
        issuer = getattr(request.app.state, "qr_issuer", None)
        if issuer is None:
            raise HTTPException(503, "QR issuance is not configured")
        return await run_in_threadpool(get_or_issue, request.app.state.database_engine, user.id, issuer)
    except SQLAlchemyError:
        raise HTTPException(503, "Credential store unavailable", headers={"Cache-Control": "no-store"}) from None
    except HTTPException as error:
        error.headers = {**(error.headers or {}), "Cache-Control": "no-store"}
        raise
