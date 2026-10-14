import base64
import re
import uuid
from typing import Literal, Protocol
from urllib.parse import unquote_plus

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy.orm import Session

from models import ClientType, SSOClient, User
from sso.authorization import consume_code
from sso.clients import verify_client_secret


class OAuthError(Exception):
    def __init__(
        self,
        error: str,
        description: str,
        status_code: int = 400,
        headers: dict[str, str] | None = None,
    ):
        super().__init__(description)
        self.error = error
        self.error_description = description
        self.status_code = status_code
        self.headers = headers or {}


class TokenRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    grant_type: str = Field(min_length=1, max_length=64)
    code: str = Field(min_length=1, max_length=512)
    redirect_uri: str = Field(min_length=1, max_length=2048)
    code_verifier: str = Field(min_length=43, max_length=128)
    client_id: str | None = Field(default=None, max_length=64)
    client_secret: str | None = Field(default=None, max_length=1024)

    @field_validator("code_verifier")
    @classmethod
    def validate_code_verifier(cls, value: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9._~-]{43,128}", value):
            raise ValueError("Invalid PKCE code_verifier format")
        return value


class TokenResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    access_token: str
    token_type: Literal["Bearer"] = "Bearer"
    expires_in: int
    id_token: str | None = None
    scope: str | None = None


class OAuthErrorResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    error: str
    error_description: str | None = None


class TokenIssuer(Protocol):
    async def issue(
        self,
        user: User,
        client: SSOClient,
        scopes: list[str],
        nonce: str | None = None,
    ) -> TokenResponse:
        ...


def authenticate_client(
    session: Session,
    authorization_header: str | None,
    form_client_id: str | None,
    form_client_secret: str | None,
) -> SSOClient:
    has_basic = authorization_header is not None and authorization_header.strip().startswith("Basic ")
    has_form = form_client_id is not None or form_client_secret is not None

    if has_basic and has_form:
        raise OAuthError("invalid_request", "Multiple client authentication mechanisms used", status_code=400)

    if has_basic:
        b64_part = authorization_header.strip()[6:].strip()
        try:
            raw_bytes = base64.b64decode(b64_part, validate=True)
            decoded = raw_bytes.decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            raise OAuthError("invalid_request", "Malformed authorization header", status_code=400) from None

        if ":" not in decoded:
            raise OAuthError("invalid_request", "Malformed authorization header", status_code=400)

        raw_id, raw_secret = decoded.split(":", 1)
        client_id = unquote_plus(raw_id)
        client_secret = unquote_plus(raw_secret)
        is_basic = True
    else:
        client_id = form_client_id
        client_secret = form_client_secret
        is_basic = False

    auth_headers = {"WWW-Authenticate": 'Basic realm="Argus"'} if is_basic else {}

    if not client_id:
        raise OAuthError("invalid_client", "Missing client credentials", status_code=401, headers=auth_headers)

    client = session.get(SSOClient, client_id)
    if client is None or not client.enabled:
        raise OAuthError("invalid_client", "Client authentication failed", status_code=401, headers=auth_headers)

    if client.client_type == ClientType.CONFIDENTIAL:
        if not client_secret:
            raise OAuthError("invalid_client", "Client secret required", status_code=401, headers=auth_headers)
        if not verify_client_secret(client, client_secret):
            raise OAuthError("invalid_client", "Client authentication failed", status_code=401, headers=auth_headers)

    return client


async def consume_token_code(
    redis_client,
    code: str,
    client_id: str,
    redirect_uri: str,
    code_verifier: str,
) -> dict:
    try:
        return await consume_code(redis_client, code, client_id, redirect_uri, code_verifier)
    except HTTPException as e:
        if e.status_code == 400:
            raise OAuthError("invalid_grant", "Invalid, expired, or revoked authorization code", status_code=400) from None
        if e.status_code == 503:
            raise OAuthError("temporarily_unavailable", "Authorization store unavailable", status_code=503) from None
        raise


def verify_token_user(session: Session, user_id_str: str) -> User:
    try:
        user_uuid = uuid.UUID(user_id_str)
    except (ValueError, TypeError):
        raise OAuthError("invalid_grant", "Invalid user identifier in authorization grant", status_code=400) from None

    user = session.get(User, user_uuid)
    if user is None or user.disabled_at is not None:
        raise OAuthError("invalid_grant", "User account is disabled or not found", status_code=400)
    return user
