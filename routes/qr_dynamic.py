"""Dynamic QR HTTP contract; authentication precedes token validation and consumption."""

import uuid

from fastapi import APIRouter, Body, Depends, HTTPException, Request
from fastapi.security import APIKeyCookie, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from auth.session import COOKIE_NAME, require_same_origin
from models import SSOClient, User
from qr.dynamic_state import DynamicStoreUnavailable, consume, revoke
from qr.dynamic_tokens import DynamicIssueResponse, MAX_TOKEN_BYTES
from qr.tokens import QRValidationError
from qr.verification import unauthorized
from routes.qr import CredentialRequest, credential_user
from routes.qr_verification import NoStoreRoute, VerificationError
from signing_keys import KeyManagementError
from sso.jwt import JWTValidationError, JWTValidator

SCOPE = "qr:dynamic:verify"
router = APIRouter(prefix="/api/v1/qr/dynamic", tags=["Dynamic QR"], route_class=NoStoreRoute)


class TokenRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    token: str = Field(min_length=1, max_length=MAX_TOKEN_BYTES,
                       description="Compact aletheia.qr.dynamic JWT. Never submit a static QR or SSO token.")


class VerifyResponse(BaseModel):
    valid: bool = Field(description="True only after the unique atomic consume. No identity or admission decision.")


class RevokeResponse(BaseModel):
    revoked: bool = Field(description="True only when this request changed the owner's ISSUED token to REVOKED.")


def issuer_for(request):
    issuer = getattr(request.app.state, "dynamic_qr_issuer", None)
    if issuer is None:
        raise HTTPException(503, "Dynamic QR is not configured")
    return issuer


def check_scanner(engine, claims):
    with Session(engine) as session:
        user = session.get(User, uuid.UUID(claims["sub"]))
        client = session.get(SSOClient, claims["client_id"])
        if user is None or user.disabled_at is not None or client is None or not client.enabled:
            raise unauthorized()
        if SCOPE not in client.allowed_scopes:
            raise insufficient_scope()


def insufficient_scope():
    return HTTPException(403, "Required scope missing", headers={
        "WWW-Authenticate": f'Bearer error="insufficient_scope", scope="{SCOPE}"'})


async def scanner(request: Request):
    authorization = request.headers.get("authorization", "").split()
    if len(authorization) != 2 or authorization[0].lower() != "bearer":
        raise HTTPException(401, "Bearer access token required", headers={"WWW-Authenticate": "Bearer"})
    issuer = getattr(request.app.state, "token_issuer", None)
    if issuer is None:
        raise HTTPException(503, "Verification is not configured")
    try:
        claims = await run_in_threadpool(JWTValidator(issuer.settings, issuer.keys).validate_access_token,
                                        authorization[1], audience=issuer.settings.access_audience)
    except JWTValidationError:
        raise unauthorized() from None
    except KeyManagementError:
        raise HTTPException(503, "Verification keys unavailable") from None
    if SCOPE not in claims["scope"].split(" "):
        raise insufficient_scope()
    try:
        await run_in_threadpool(check_scanner, request.app.state.database_engine, claims)
    except SQLAlchemyError:
        raise HTTPException(503, "Verification store unavailable") from None


def no_query(request):
    if request.query_params:
        raise HTTPException(400, "Query parameters are unsupported")


ERRORS = {code: {"model": VerificationError, "description": description}
          for code, description in ((400, "Unsupported query or invalid revoke token"),
                                    (401, "Missing or invalid session / Access Token"),
                                    (403, "Wrong Origin, insufficient scope or another token owner"),
                                    (422, "Invalid body; submitted tokens are never echoed"),
                                    (503, "Keys, database or Redis unavailable; fails closed"))}
ORIGIN = {"parameters": [{"in": "header", "name": "Origin", "required": True,
                           "schema": {"type": "string"}, "description": "Exact SESSION_PUBLIC_ORIGIN"}]}
COOKIE = [Depends(APIKeyCookie(name=COOKIE_NAME, auto_error=False))]


@router.post("/issue", response_model=DynamicIssueResponse, responses=ERRORS, dependencies=COOKIE,
             openapi_extra=ORIGIN, summary="Issue a new 30-second dynamic QR",
             description="Browser session and exact Origin required. Omit body or send {}. Refresh every 25 seconds. "
                         "Each issuance registers a new random jti in Redis before returning it. Earlier tokens remain "
                         "valid until their own expiry or consumption/revocation. All responses are no-store.")
async def issue(request: Request, body: CredentialRequest | None = Body(default=None),
                user: User = Depends(credential_user)):
    require_same_origin(request)
    no_query(request)
    try:
        return await issuer_for(request).issue(request.app.state.redis_client, user.id)
    except (DynamicStoreUnavailable, KeyManagementError):
        raise HTTPException(503, "Dynamic QR issuance unavailable") from None


@router.post("/verify", response_model=VerifyResponse, responses=ERRORS,
             dependencies=[Depends(HTTPBearer(auto_error=False)), Depends(scanner)],
             summary="Verify and consume a dynamic QR exactly once",
             description="SSO Access Token for SSO_ACCESS_AUDIENCE with qr:dynamic:verify scope required. "
                         "Token failures return 200 with valid=false without revealing the cause. Redis uncertainty "
                         "returns 503 and may already have spent the token. No identity information is returned.")
async def verify(request: Request, body: TokenRequest):
    no_query(request)
    issuer = issuer_for(request)
    try:
        claims = await run_in_threadpool(issuer.validate, body.token)
        return VerifyResponse(valid=await consume(request.app.state.redis_client, claims))
    except QRValidationError:
        return VerifyResponse(valid=False)
    except (DynamicStoreUnavailable, KeyManagementError):
        raise HTTPException(503, "Dynamic QR verification unavailable") from None


@router.post("/revoke", response_model=RevokeResponse, responses=ERRORS, dependencies=COOKIE,
             openapi_extra=ORIGIN, summary="Revoke the browser user's own dynamic QR",
             description="Browser session and exact Origin required. Accepts the signed token, never an arbitrary jti. "
                         "Only its owner may revoke it. Terminal/missing states return revoked=false; invalid signed "
                         "tokens return 400, another owner 403, and Redis uncertainty 503. All responses are no-store.")
async def revoke_token(request: Request, body: TokenRequest, user: User = Depends(credential_user)):
    require_same_origin(request)
    no_query(request)
    try:
        claims = await run_in_threadpool(issuer_for(request).validate, body.token)
        if claims["sub"] != str(user.id):
            raise HTTPException(403, "Token owner required")
        return RevokeResponse(revoked=await revoke(request.app.state.redis_client, claims))
    except QRValidationError:
        raise HTTPException(400, "Invalid dynamic QR token") from None
    except (DynamicStoreUnavailable, KeyManagementError):
        raise HTTPException(503, "Dynamic QR revocation unavailable") from None
