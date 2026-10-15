"""Argus SSO tokens. Key storage and lifecycle belong to the key provider (#16)."""

import os
import secrets
import time
import uuid
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import urlsplit

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from models import SSOClient, User
from signing_keys import KeyManagementError
from sso.clients import validate_scopes
from sso.token import TokenResponse


class VerificationKeys(Protocol):
    def verification_key(self, purpose: str, kid: str) -> Ed25519PublicKey | None:
        """Return a trusted active/verify-only public key; unknown/retired keys return None."""
        ...


class SigningKeys(VerificationKeys, Protocol):
    def signing_key(self, purpose: str) -> tuple[str, Ed25519PrivateKey]:
        """Return the current active key ID and key, or raise if unavailable."""
        ...


@dataclass(frozen=True)
class JWTSettings:
    issuer: str
    access_audience: str
    access_ttl: int = 300
    id_ttl: int = 300

    def __post_init__(self):
        uri = urlsplit(self.issuer)
        if (not uri.hostname or uri.username or uri.password or "?" in self.issuer
                or "#" in self.issuer or any(ord(c) <= 32 for c in self.issuer)
                or (uri.scheme != "https" and not (
                    uri.scheme == "http" and uri.hostname in {"localhost", "127.0.0.1", "::1"}))):
            raise ValueError("JWT issuer must be HTTPS (or loopback HTTP), without credentials, query or fragment")
        if not self.access_audience or self.access_audience != self.access_audience.strip():
            raise ValueError("An explicit access token resource audience is required")
        if any(type(ttl) is not int or not 1 <= ttl <= 3600 for ttl in (self.access_ttl, self.id_ttl)):
            raise ValueError("JWT lifetimes must be between 1 and 3600 seconds")

    @classmethod
    def from_environment(cls):
        return cls(
            issuer=os.environ["SSO_ISSUER"],
            access_audience=os.environ["SSO_ACCESS_AUDIENCE"],
            access_ttl=int(os.getenv("SSO_ACCESS_TOKEN_TTL_SECONDS", "300")),
            id_ttl=int(os.getenv("SSO_ID_TOKEN_TTL_SECONDS", "300")),
        )


class JWTValidationError(ValueError):
    """Invalid credential. Never include the credential in an error message."""


class JWTIssuer:
    def __init__(self, settings: JWTSettings, keys: SigningKeys):
        self.settings = settings
        self.keys = keys

    async def issue(self, user: User, client: SSOClient, scopes: list[str], nonce: str | None = None) -> TokenResponse:
        if user.disabled_at is not None or not client.enabled:
            raise ValueError("User or client is disabled")
        subject = str(uuid.UUID(str(user.id)))
        validate_scopes(scopes)
        if not scopes or not client.client_id or not set(scopes).issubset(client.allowed_scopes):
            raise ValueError("Invalid token grant")
        if nonce is not None and (not isinstance(nonce, str) or not nonce):
            raise ValueError("Invalid nonce")
        # Timestamp before taking the signing snapshot so an in-flight issuance
        # cannot extend an old key's TTL beyond its rotation retention deadline.
        now = int(time.time())
        kid, key = self.keys.signing_key("sso")
        if not isinstance(kid, str) or not kid or not isinstance(key, Ed25519PrivateKey):
            raise ValueError("An active SSO Ed25519 signing key is required")
        common = {"iss": self.settings.issuer, "sub": subject, "iat": now}

        def sign(claims, typ):
            return jwt.encode(claims, key, algorithm="EdDSA", headers={"kid": kid, "typ": typ})

        scope = " ".join(scopes)
        access_token = sign({
            **common, "aud": self.settings.access_audience, "exp": now + self.settings.access_ttl,
            "token_use": "access_token", "scope": scope, "client_id": client.client_id,
            "jti": secrets.token_urlsafe(32),
        }, "at+jwt")
        id_token = None
        if "openid" in scopes:
            claims = {**common, "aud": client.client_id, "exp": now + self.settings.id_ttl, "token_use": "id_token"}
            if nonce is not None:
                claims["nonce"] = nonce
            id_token = sign(claims, "JWT")
        return TokenResponse(access_token=access_token, expires_in=self.settings.access_ttl, id_token=id_token, scope=scope)


class JWTValidator:
    def __init__(self, settings: JWTSettings, keys: VerificationKeys):
        self.settings = settings
        self.keys = keys

    def validate_access_token(self, token: str, *, audience: str, required_scopes: tuple[str, ...] = ()) -> dict:
        """The resource server must supply its own audience and required permissions."""
        claims = self._validate(token, audience, "access_token", "at+jwt", self.settings.access_ttl)
        try:
            scope = claims["scope"]
            if not isinstance(scope, str) or not scope:
                raise ValueError()
            scopes = scope.split(" ")
            validate_scopes(scopes)
            if not set(required_scopes).issubset(scopes):
                raise ValueError()
            if any(not isinstance(claims.get(k), str) or not claims[k] for k in ("client_id", "jti")):
                raise ValueError()
        except (KeyError, ValueError, TypeError):
            raise JWTValidationError("Invalid access token permissions or claims") from None
        return claims

    def validate_id_token(self, token: str, *, client_id: str, nonce: str | None = None) -> dict:
        """Pass the nonce saved with the original authorization request, when used."""
        claims = self._validate(token, client_id, "id_token", "JWT", self.settings.id_ttl)
        actual = claims.get("nonce")
        if (("nonce" in claims and (not isinstance(actual, str) or not actual))
                or (nonce is not None and actual != nonce)):
            raise JWTValidationError("Invalid ID token nonce")
        return claims

    def _validate(self, token: str, audience: str, token_use: str, typ: str, ttl: int) -> dict:
        try:
            if not isinstance(audience, str) or not audience:
                raise ValueError()
            header = jwt.get_unverified_header(token)
            kid = header.get("kid")
            if (header.get("alg") != "EdDSA" or header.get("typ") != typ
                    or not isinstance(kid, str) or not kid or "crit" in header or "b64" in header):
                raise ValueError()
            # Header data selects only a key from a trusted, purpose-scoped provider.
            # Never follow jku/x5u URLs or accept a supplied jwk.
            key = self.keys.verification_key("sso", kid)
            if not isinstance(key, Ed25519PublicKey):
                raise ValueError()
            claims = jwt.decode(
                token, key, algorithms=["EdDSA"], issuer=self.settings.issuer, audience=audience,
                options={"require": ["iss", "sub", "aud", "iat", "exp", "token_use"], "strict_aud": True},
            )
            if claims["token_use"] != token_use:
                raise ValueError()
            if any(type(claims[k]) is not int or claims[k] < 0 for k in ("iat", "exp")):
                raise ValueError()
            if not 0 < claims["exp"] - claims["iat"] <= ttl:
                raise ValueError()
            if str(uuid.UUID(claims["sub"])) != claims["sub"]:
                raise ValueError()
            return claims
        except KeyManagementError:
            raise
        except (jwt.PyJWTError, ValueError, TypeError, KeyError, AttributeError, OverflowError):
            raise JWTValidationError("Invalid SSO token") from None
