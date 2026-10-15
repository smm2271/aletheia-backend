import base64
import hashlib
import json
import os
import re
import secrets
import time
from typing import Literal
from urllib.parse import urlencode

from fastapi import HTTPException
from pydantic import BaseModel, Field, ValidationError, model_validator
from redis.exceptions import RedisError
from sqlalchemy.orm import Session

from auth.session import SessionError
from models import ClientType, TrustLevel
from sso.clients import validate_client_request, validate_redirects, validate_scopes

CONTEXT_COOKIE = "aletheia_authorization"
CONTEXT_TTL = 600
CONTEXT_PREFIX = "aletheia:authorization-context:"
CODE_PREFIX = "aletheia:authorization-code:"


class AuthorizationRequest(BaseModel):
    response_type: Literal["code"]
    client_id: str = Field(min_length=1, max_length=64)
    redirect_uri: str = Field(min_length=1, max_length=2048)
    scope: str = Field(min_length=1, max_length=4096)
    state: str | None = Field(default=None, max_length=4096)
    nonce: str | None = Field(default=None, min_length=1, max_length=512)
    code_challenge: str | None = None
    code_challenge_method: str | None = None

    @property
    def scopes(self):
        return self.scope.split(" ")

    @model_validator(mode="after")
    def validate_request(self):
        validate_scopes(self.scopes)
        if self.code_challenge is not None or self.code_challenge_method is not None:
            if self.code_challenge_method != "S256" or not re.fullmatch(r"[A-Za-z0-9_-]{43}", self.code_challenge or ""):
                raise ValueError("Only PKCE S256 is supported")
        return self


def parse_request(query) -> AuthorizationRequest:
    values = {}
    for key in AuthorizationRequest.model_fields:
        if len(query.getlist(key)) > 1:
            raise HTTPException(400, "Duplicate authorization parameter")
        if key in query:
            values[key] = query[key]
    try:
        return AuthorizationRequest.model_validate(values)
    except ValidationError:
        raise HTTPException(400, "Invalid authorization request") from None


def validate_request(engine, params: AuthorizationRequest):
    with Session(engine) as session:
        client = validate_client_request(session, params.client_id, params.redirect_uri, params.scopes)
        try:
            validate_redirects([params.redirect_uri])
        except ValueError:
            raise HTTPException(400, "Invalid registered redirect URI") from None
        if params.code_challenge is None or params.code_challenge_method != "S256":
            raise HTTPException(400, "All clients require PKCE S256")
        return client


def context_fingerprint(token: str | None) -> str | None:
    if not token or not re.fullmatch(r"[A-Za-z0-9_-]{43}", token):
        return None
    return hashlib.sha256(token.encode("ascii")).hexdigest()


async def store_context(client, params: AuthorizationRequest) -> str:
    record = json.dumps({"request": params.model_dump(), "expires_at": int(time.time()) + CONTEXT_TTL})
    try:
        for _ in range(3):
            token = secrets.token_urlsafe(32)
            if await client.set(CONTEXT_PREFIX + context_fingerprint(token), record, ex=CONTEXT_TTL, nx=True):
                return token
    except RedisError:
        raise SessionError(503, "Authorization store unavailable") from None
    raise SessionError(503, "Unable to preserve authorization request")


async def consume_context(client, token: str | None) -> AuthorizationRequest:
    fingerprint = context_fingerprint(token)
    if fingerprint is None:
        raise HTTPException(400, "Invalid or expired authorization continuation")
    try:
        raw = await client.getdel(CONTEXT_PREFIX + fingerprint)
    except RedisError:
        raise SessionError(503, "Authorization store unavailable") from None
    try:
        record = json.loads(raw)
        if type(record["expires_at"]) is not int or record["expires_at"] <= int(time.time()):
            raise ValueError()
        return AuthorizationRequest.model_validate(record["request"])
    except (TypeError, KeyError, ValueError):
        raise HTTPException(400, "Invalid or expired authorization continuation") from None


def code_ttl() -> int:
    try:
        ttl = int(os.getenv("AUTHORIZATION_CODE_TTL_SECONDS", "120"))
        if not 1 <= ttl <= 600:
            raise ValueError()
        return ttl
    except ValueError:
        raise SessionError(503, "Invalid authorization code configuration") from None


async def issue_code(client, user_id, params: AuthorizationRequest) -> str:
    now, ttl = int(time.time()), code_ttl()
    record = json.dumps({
        "user_id": str(user_id), "client_id": params.client_id, "redirect_uri": params.redirect_uri,
        "scope": params.scopes, "nonce": params.nonce, "created_at": now, "expires_at": now + ttl,
        "code_challenge": params.code_challenge, "code_challenge_method": params.code_challenge_method,
    })
    try:
        for _ in range(3):
            code = secrets.token_urlsafe(32)
            if await client.set(CODE_PREFIX + context_fingerprint(code), record, ex=ttl, nx=True):
                return code
    except RedisError:
        raise SessionError(503, "Authorization store unavailable") from None
    raise SessionError(503, "Unable to create authorization code")


async def consume_code(client, code: str, client_id: str, redirect_uri: str, code_verifier: str | None = None) -> dict:
    """Internal exchange primitive; callers must first authenticate the Client.

    Match binding before deletion so wrong-client requests cannot burn a code.
    No Token Endpoint is exposed by this issue.
    """
    fingerprint = context_fingerprint(code)
    if fingerprint is None:
        raise HTTPException(400, "Invalid authorization code")
    challenge = ""
    if code_verifier and re.fullmatch(r"[A-Za-z0-9._~-]{43,128}", code_verifier):
        challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode("ascii")).digest()).rstrip(b"=").decode()
    script = """
        local raw = redis.call('GET', KEYS[1])
        if not raw then return nil end
        local ok, record = pcall(cjson.decode, raw)
        if not ok or type(record) ~= 'table' or type(record.expires_at) ~= 'number' then
            redis.call('DEL', KEYS[1]); return nil
        end
        if record.expires_at <= tonumber(ARGV[3]) then redis.call('DEL', KEYS[1]); return nil end
        if record.client_id ~= ARGV[1] or record.redirect_uri ~= ARGV[2] then return nil end
        if record.code_challenge ~= cjson.null and record.code_challenge ~= ARGV[4] then return nil end
        redis.call('DEL', KEYS[1])
        return raw
    """
    try:
        raw = await client.eval(script, 1, CODE_PREFIX + fingerprint, client_id, redirect_uri, int(time.time()), challenge)
    except RedisError:
        raise SessionError(503, "Authorization store unavailable") from None
    if raw is None:
        raise HTTPException(400, "Invalid authorization code")
    return json.loads(raw)


def callback_uri(params: AuthorizationRequest, code: str) -> str:
    query = [("code", code)]
    if params.state is not None:
        query.append(("state", params.state))
    separator = "" if params.redirect_uri.endswith(("?", "&")) else ("&" if "?" in params.redirect_uri else "?")
    return params.redirect_uri + separator + urlencode(query)


def consent_required(client) -> bool:
    return client.trust_level != TrustLevel.FIRST_PARTY
