"""Online static QR verification; does not make an admission decision."""

import hmac
import uuid
from datetime import datetime, timezone
from typing import Literal

from fastapi import HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from models import QRCredential, SSOClient, User
from qr.tokens import MAX_TOKEN_BYTES, QRValidationError, QRValidator
from signing_keys import KeyManagementError
from sso.jwt import JWTValidationError, JWTValidator

SCOPE = "qr:static:verify"


class VerificationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    token: str = Field(min_length=1, max_length=MAX_TOKEN_BYTES)
    nonce: str = Field(min_length=1, max_length=64)


class VerificationResponse(BaseModel):
    valid: Literal[True] = True


def unauthorized():
    return HTTPException(401, "Invalid access token", headers={"WWW-Authenticate": 'Bearer error="invalid_token"'})


def forbidden():
    return HTTPException(403, "Required scope missing", headers={
        "WWW-Authenticate": f'Bearer error="insufficient_scope", scope="{SCOPE}"',
    })


def verify_mapping(engine, access_claims, validator: QRValidator, token: str) -> str:
    with Session(engine) as session:
        scanner = session.get(User, uuid.UUID(access_claims["sub"]))
        client = session.get(SSOClient, access_claims["client_id"])
        if scanner is None or scanner.disabled_at is not None or client is None or not client.enabled:
            raise unauthorized()
        if SCOPE not in client.allowed_scopes:
            raise forbidden()
        try:
            claims = validator.validate(token)
        except QRValidationError:
            raise HTTPException(400, "Invalid QR credential") from None
        record = session.scalar(select(QRCredential).where(QRCredential.credential_id == claims["cid"]))
        scanned_user = session.get(User, record.user_id) if record is not None else None
        if (record is None or scanned_user is None or scanned_user.disabled_at is not None
                or not hmac.compare_digest(record.token.encode("utf-8"), token.encode("utf-8"))
                or record.issued_at.timestamp() != claims["iat"]
                or record.expires_at.timestamp() != claims["exp"]
                or datetime.now(timezone.utc) >= record.expires_at):
            raise HTTPException(400, "Invalid QR credential")
        return client.client_id


async def verify_for_client(request: Request, token: str) -> str:
    """Authenticate the scanner and resolve a currently valid QR; return only client ID."""
    try:
        authorization = request.headers.get("authorization", "").split()
        if len(authorization) != 2 or authorization[0].lower() != "bearer":
            raise HTTPException(401, "Bearer access token required", headers={"WWW-Authenticate": "Bearer"})
        issuer = getattr(request.app.state, "token_issuer", None)
        qr_issuer = getattr(request.app.state, "qr_issuer", None)
        if issuer is None or qr_issuer is None:
            raise HTTPException(503, "Verification is not configured")
        validator = JWTValidator(issuer.settings, issuer.keys)
        try:
            claims = await run_in_threadpool(validator.validate_access_token, authorization[1],
                                            audience=issuer.settings.access_audience)
        except JWTValidationError:
            raise unauthorized() from None
        if SCOPE not in claims["scope"].split(" "):
            raise forbidden()
        qr_validator = QRValidator(qr_issuer.settings, qr_issuer.keys)
        return await run_in_threadpool(verify_mapping, request.app.state.database_engine, claims, qr_validator, token)
    except KeyManagementError:
        raise HTTPException(503, "Verification keys unavailable", headers={"Cache-Control": "no-store"}) from None
    except SQLAlchemyError:
        raise HTTPException(503, "Verification store unavailable", headers={"Cache-Control": "no-store"}) from None
    except HTTPException as error:
        error.headers = {**(error.headers or {}), "Cache-Control": "no-store"}
        raise
