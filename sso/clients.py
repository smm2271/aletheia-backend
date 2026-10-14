import base64
import hashlib
import re
import secrets
from urllib.parse import parse_qsl, urlsplit

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy.orm import Session

from models import ClientType, SSOClient, TrustLevel


def validate_redirects(values: list[str]) -> list[str]:
    if len(values) != len(set(values)):
        raise ValueError("Redirect URIs must be distinct")
    for value in values:
        try:
            uri = urlsplit(value)
            if (value != value.strip() or len(value) > 2048 or "*" in value
                    or uri.scheme not in {"http", "https"} or not uri.hostname
                    or uri.username or uri.password or uri.fragment
                    or (uri.scheme == "http" and uri.hostname not in {"localhost", "127.0.0.1", "::1"})
                    or any(k in {"code", "state", "error", "error_description"} for k, v in parse_qsl(uri.query))):
                raise ValueError()
            uri.port
        except ValueError:
            raise ValueError("Redirect URI must be HTTPS (or loopback HTTP), without credentials, fragments, wildcards or reserved response parameters") from None
    return values  # Keep the exact registered string; do not canonicalize.


def validate_scopes(values: list[str]) -> list[str]:
    if len(values) != len(set(values)) or any(not re.fullmatch(r'[\x21\x23-\x5b\x5d-\x7e]{1,128}', s) for s in values):
        raise ValueError("Scopes must be distinct OAuth scope tokens")
    return values


class ClientCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=255)
    client_type: ClientType
    trust_level: TrustLevel
    enabled: bool = True
    redirect_uris: list[str] = Field(min_length=1, max_length=20)
    allowed_scopes: list[str] = Field(min_length=1, max_length=32)
    _redirects = field_validator("redirect_uris")(validate_redirects)
    _scopes = field_validator("allowed_scopes")(validate_scopes)


class ClientPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str | None = Field(default=None, min_length=1, max_length=255)
    trust_level: TrustLevel | None = None
    enabled: bool | None = None
    redirect_uris: list[str] | None = Field(default=None, min_length=1, max_length=20)
    allowed_scopes: list[str] | None = Field(default=None, min_length=1, max_length=32)

    @field_validator("name", "trust_level", "enabled", "redirect_uris", "allowed_scopes")
    @classmethod
    def not_null(cls, value):
        if value is None:
            raise ValueError("Fields cannot be null")
        return value

    _redirects = field_validator("redirect_uris")(validate_redirects)
    _scopes = field_validator("allowed_scopes")(validate_scopes)


def hash_secret(secret: str) -> str:
    salt = secrets.token_bytes(16)
    value = hashlib.scrypt(secret.encode(), salt=salt, n=16384, r=8, p=1, dklen=32)
    return "scrypt$" + base64.b64encode(salt).decode() + "$" + base64.b64encode(value).decode()


def verify_client_secret(client: SSOClient, secret: str | None) -> bool:
    if not client.enabled or client.client_type != ClientType.CONFIDENTIAL or not secret or len(secret) > 1024:
        return False
    try:
        algorithm, salt, expected = client.secret_hash.split("$")
        if algorithm != "scrypt":
            return False
        actual = hashlib.scrypt(secret.encode(), salt=base64.b64decode(salt, validate=True), n=16384, r=8, p=1, dklen=32)
        return secrets.compare_digest(actual, base64.b64decode(expected, validate=True))
    except (ValueError, AttributeError):
        return False


def new_secret() -> tuple[str, str]:
    secret = secrets.token_urlsafe(32)
    return secret, hash_secret(secret)


def client_profile(client: SSOClient) -> dict:
    return {k: getattr(client, k) for k in (
        "client_id", "name", "client_type", "trust_level", "enabled", "redirect_uris", "allowed_scopes", "created_at", "updated_at",
    )}


def validate_client_request(session: Session, client_id: str, redirect_uri: str, scopes: list[str]) -> SSOClient:
    client = session.get(SSOClient, client_id)
    if client is None or not client.enabled:
        raise HTTPException(400, "Invalid or disabled client")
    if redirect_uri not in client.redirect_uris:
        raise HTTPException(400, "Unregistered redirect URI")
    if not scopes or any(scope not in client.allowed_scopes for scope in scopes):
        raise HTTPException(400, "Scope is not allowed")
    return client
