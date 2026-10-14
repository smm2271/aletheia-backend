import hashlib
import json
import os
import re
import secrets
import time
import uuid
from dataclasses import dataclass
from urllib.parse import urlsplit

from fastapi import HTTPException, Request
from redis.exceptions import RedisError
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from models import User

COOKIE_NAME = "aletheia_session"
KEY_PREFIX = "aletheia:session:"


class SessionError(HTTPException):
    def __init__(self, status: int, detail: str):
        super().__init__(status_code=status, detail=detail)
        self.status = status


@dataclass(frozen=True)
class SessionSettings:
    ttl: int
    secure_cookie: bool
    public_origin: str

    @classmethod
    def from_environment(cls):
        try:
            ttl = int(os.getenv("SESSION_TTL_SECONDS", "28800"))
            secure = os.getenv("SESSION_COOKIE_SECURE", "true").lower()
            origin = os.getenv("SESSION_PUBLIC_ORIGIN", "").strip()
            if not origin:
                redirect = urlsplit(os.getenv("GOOGLE_REDIRECT_URI", ""))
                origin = f"{redirect.scheme}://{redirect.netloc}"
            parsed = urlsplit(origin)
            if (not 1 <= ttl <= 2592000 or secure not in {"true", "false"}
                    or parsed.scheme not in {"http", "https"} or not parsed.hostname
                    or parsed.username or parsed.password or parsed.query or parsed.fragment
                    or parsed.path not in {"", "/"}
                    or (parsed.scheme == "http" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"})
                    or (secure == "false" and parsed.scheme != "http")):
                raise ValueError()
            parsed.port  # Reject malformed ports without echoing configuration.
            return cls(ttl, secure == "true", f"{parsed.scheme}://{parsed.netloc}")
        except ValueError:
            raise SessionError(503, "Invalid session configuration") from None


def session_key(token: str | None) -> str | None:
    if not token or not re.fullmatch(r"[A-Za-z0-9_-]{43}", token):
        return None
    return KEY_PREFIX + hashlib.sha256(token.encode("ascii")).hexdigest()


async def create_session(client, user_id: uuid.UUID, settings: SessionSettings, previous: str | None = None) -> str:
    now = int(time.time())
    record = json.dumps({"user_id": str(user_id), "created_at": now, "expires_at": now + settings.ttl})
    # Creation and revocation of the old browser session happen atomically.
    script = """
        if redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[2], 'NX') then
            if KEYS[2] ~= KEYS[1] then redis.call('DEL', KEYS[2]) end
            return 1
        end
        return 0
    """
    try:
        for _ in range(3):
            token = secrets.token_urlsafe(32)
            key = session_key(token)
            old_key = session_key(previous) or key
            if await client.eval(script, 2, key, old_key, record, settings.ttl):
                return token
    except RedisError:
        raise SessionError(503, "Session store unavailable") from None
    raise SessionError(503, "Unable to create session")


async def revoke_session(client, token: str | None) -> None:
    key = session_key(token)
    if key:
        try:
            await client.delete(key)
        except RedisError:
            raise SessionError(503, "Session store unavailable") from None


async def read_session(client, token: str | None) -> uuid.UUID:
    key = session_key(token)
    if key is None:
        raise SessionError(401, "Unauthenticated")
    try:
        raw = await client.get(key)
    except RedisError:
        raise SessionError(503, "Session store unavailable") from None
    if raw is None:
        raise SessionError(401, "Unauthenticated")
    try:
        record = json.loads(raw)
        now = int(time.time())
        if (not isinstance(record, dict) or type(record.get("created_at")) is not int
                or type(record.get("expires_at")) is not int
                or not record["created_at"] <= now < record["expires_at"]):
            raise ValueError()
        return uuid.UUID(record["user_id"])
    except (ValueError, KeyError, TypeError, AttributeError):
        await revoke_session(client, token)
        raise SessionError(401, "Unauthenticated") from None


def set_session_cookie(response, token: str, settings: SessionSettings) -> None:
    response.set_cookie(
        COOKIE_NAME, token, max_age=settings.ttl, path="/", httponly=True,
        secure=settings.secure_cookie, samesite="lax",
    )


def clear_session_cookie(response) -> None:
    secure = os.getenv("SESSION_COOKIE_SECURE", "true").lower() == "true"
    response.delete_cookie(COOKIE_NAME, path="/", httponly=True, samesite="lax", secure=secure)


def user_profile(user: User) -> dict:
    return {
        "id": str(user.id), "email": user.email, "username": user.username,
        "avatar_url": user.avatar_url, "affiliation": user.affiliation.value,
    }


def load_user(engine, user_id: uuid.UUID) -> User | None:
    with Session(engine) as session:
        return session.get(User, user_id)


async def get_current_user(request: Request) -> User:
    token = request.cookies.get(COOKIE_NAME)
    user_id = await read_session(request.app.state.redis_client, token)
    user = await run_in_threadpool(load_user, request.app.state.database_engine, user_id)
    if user is None or user.disabled_at is not None:
        await revoke_session(request.app.state.redis_client, token)
        raise SessionError(401, "Unauthenticated")
    return user
