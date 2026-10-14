import base64
import hashlib
import os
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode, urlsplit

import httpx
from google.auth import exceptions as google_errors
from google.auth.transport.requests import Request as GoogleRequest
from google.oauth2 import id_token
from sqlalchemy import delete, func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from models import ExternalIdentity, OAuthAttempt, User
from auth import affiliation

ATTEMPT_TTL = 600
COOKIE_NAME = "google_oauth_flow"
COOKIE_PATH = "/auth/google"
AUTHORIZATION_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"


class OAuthError(Exception):
    def __init__(self, status: int, detail: str):
        self.status = status
        self.detail = detail
        super().__init__(detail)


@dataclass(frozen=True)
class GoogleSettings:
    client_id: str
    client_secret: str = field(repr=False)
    redirect_uri: str
    hosted_domain: str | None = None

    @property
    def secure_cookie(self) -> bool:
        return urlsplit(self.redirect_uri).scheme == "https"

    @classmethod
    def from_environment(cls):
        values = [os.getenv(key, "").strip() for key in (
            "GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET", "GOOGLE_REDIRECT_URI",
        )]
        if not all(values):
            raise OAuthError(503, "Google OAuth is not configured")
        try:
            parsed = urlsplit(values[2])
            hostname = parsed.hostname
        except ValueError:
            raise OAuthError(503, "Invalid Google redirect configuration") from None
        if (parsed.scheme not in {"http", "https"} or not hostname
                or parsed.username or parsed.password or parsed.query or parsed.fragment
                or parsed.path != "/auth/google/callback"
                or (parsed.scheme == "http" and hostname not in {"localhost", "127.0.0.1", "::1"})):
            raise OAuthError(503, "Invalid Google redirect configuration")
        return cls(*values, os.getenv("GOOGLE_HOSTED_DOMAIN", "").strip().lower() or None)


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def begin_login(session: Session, settings: GoogleSettings) -> tuple[str, str]:
    state, browser, nonce = (secrets.token_urlsafe(32) for _ in range(3))
    verifier = secrets.token_urlsafe(64)
    session.execute(delete(OAuthAttempt).where(OAuthAttempt.expires_at <= func.now()))
    session.add(OAuthAttempt(
        state_hash=digest(state), browser_hash=digest(browser), nonce=nonce,
        code_verifier=verifier, expires_at=datetime.now(timezone.utc) + timedelta(seconds=ATTEMPT_TTL),
    ))
    session.commit()
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")
    params = {
        "client_id": settings.client_id, "redirect_uri": settings.redirect_uri,
        "response_type": "code", "scope": "openid email profile", "state": state,
        "nonce": nonce, "code_challenge": challenge, "code_challenge_method": "S256",
    }
    if settings.hosted_domain:
        params["hd"] = settings.hosted_domain
    return AUTHORIZATION_URL + "?" + urlencode(params), browser


def consume_attempt(session: Session, state: str | None, browser: str | None) -> tuple[str, str]:
    if not state or not browser or len(state) > 128 or len(browser) > 128:
        raise OAuthError(400, "Invalid or expired OAuth state")
    attempt = session.execute(delete(OAuthAttempt).where(
        OAuthAttempt.state_hash == digest(state), OAuthAttempt.browser_hash == digest(browser),
        OAuthAttempt.expires_at > func.now(),
    ).returning(OAuthAttempt.nonce, OAuthAttempt.code_verifier)).first()
    session.commit()  # Consume even when the provider refuses or verification fails.
    if attempt is None:
        raise OAuthError(400, "Invalid or expired OAuth state")
    return attempt.nonce, attempt.code_verifier


class BoundedGoogleRequest(GoogleRequest):
    def __call__(self, *args, **kwargs):
        kwargs["timeout"] = 10
        return super().__call__(*args, **kwargs)


def exchange_identity(code: str, verifier: str, nonce: str, settings: GoogleSettings) -> dict:
    try:
        with httpx.Client(timeout=10, follow_redirects=False) as client:
            response = client.post(TOKEN_URL, data={
                "code": code, "code_verifier": verifier, "client_id": settings.client_id,
                "client_secret": settings.client_secret, "redirect_uri": settings.redirect_uri,
                "grant_type": "authorization_code",
            })
        if response.status_code != 200:
            raise OAuthError(502 if response.status_code >= 500 else 401, "Google token exchange failed")
        tokens = response.json()
        token = tokens.get("id_token") if isinstance(tokens, dict) else None
        if not isinstance(token, str) or not token:
            raise OAuthError(401, "Google identity verification failed")
        claims = id_token.verify_oauth2_token(token, BoundedGoogleRequest(), audience=settings.client_id)
    except (httpx.HTTPError, google_errors.TransportError):
        raise OAuthError(502, "Google authentication service unavailable") from None
    except (ValueError, KeyError, TypeError, google_errors.GoogleAuthError):
        raise OAuthError(401, "Google identity verification failed") from None
    validate_claims(claims, nonce, settings)
    return claims


def validate_claims(claims: dict, nonce: str, settings: GoogleSettings) -> None:
    # Signature, issuer, audience and timestamps have already been verified by google-auth.
    if (not isinstance(claims.get("nonce"), str) or not claims["nonce"].isascii()
            or not secrets.compare_digest(claims["nonce"], nonce)
            or claims.get("email_verified") is not True
            or not isinstance(claims.get("sub"), str) or not 0 < len(claims["sub"]) <= 255
            or not claims["sub"].isascii()
            or not isinstance(claims.get("email"), str) or not 0 < len(claims["email"]) <= 320
            or "@" not in claims["email"]
            or (claims.get("azp") is not None and claims["azp"] != settings.client_id)):
        raise OAuthError(401, "Google identity verification failed")
    if settings.hosted_domain and claims.get("hd") != settings.hosted_domain:
        raise OAuthError(403, "Google Workspace domain is not allowed")


def resolve_user(session: Session, claims: dict, settings: GoogleSettings) -> User:
    # Serialize provisioning for this subject across processes. Unique constraints
    # remain authoritative for unrelated subjects with colliding business emails.
    lock_key = int.from_bytes(hashlib.sha256(("google:" + claims["sub"]).encode()).digest()[:8], "big", signed=True)
    session.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": lock_key})
    identity = session.scalar(select(ExternalIdentity).where(
        ExternalIdentity.provider == "google", ExternalIdentity.subject == claims["sub"],
    ))
    if identity:
        user = session.scalar(select(User).where(User.id == identity.user_id).with_for_update())
        if user.disabled_at is not None:
            raise OAuthError(403, "Account is disabled")
    else:
        user_affiliation = affiliation.determine_affiliation(claims)
        if user_affiliation is None:
            raise OAuthError(403, "No matching campus affiliation rule")
        user = User(affiliation=user_affiliation)
        user.external_identities.append(ExternalIdentity(provider="google", subject=claims["sub"]))
        session.add(user)
    user.email = claims["email"]
    if isinstance(claims.get("name"), str):
        user.username = claims["name"][:255]
    if isinstance(claims.get("picture"), str):
        user.avatar_url = claims["picture"]
    try:
        session.commit()
    except IntegrityError:
        session.rollback()
        raise OAuthError(409, "Email is already in use; account linking is required") from None
    session.refresh(user)
    return user
