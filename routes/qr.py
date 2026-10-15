from fastapi import APIRouter, Depends, HTTPException, Request, Response
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
                          "This endpoint does not validate entry eligibility or authorize admission."),
             dependencies=[Depends(APIKeyCookie(name=COOKIE_NAME, auto_error=False))],
             responses={code: {"model": CredentialError, "description": description} for code, description in (
                 (400, "Only self-issuance is supported"), (401, "Browser session missing or user disabled"),
                 (403, "Origin does not match"), (409, "Existing credential is unavailable until expiry"),
                 (503, "Signing keys or database unavailable"))})
async def issue_credential(request: Request, response: Response, body: CredentialRequest | None = None,
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
