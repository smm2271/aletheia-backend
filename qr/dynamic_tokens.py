"""Strict dynamic QR format. Signature validity alone never authorizes a scan."""

import base64
import json
import re
import secrets
import time
import uuid
from datetime import datetime, timezone
from typing import Literal

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import BaseModel, Field

from qr.tokens import QRSettings, QRValidationError, _invalid_constant, _unique_object
from signing_keys import KeyManagementError

TOKEN_TYPE = "aletheia.qr.dynamic"
AUDIENCE = "argus-qr-dynamic-verifier"
TTL = 30
REFRESH_AFTER = 25
MAX_TOKEN_BYTES = 2048
CLAIMS = {"v", "typ", "iss", "sub", "aud", "jti", "iat", "nbf", "exp"}


class DynamicIssueResponse(BaseModel):
    token: str = Field(description="Signed bearer secret; encode directly into the QR. Never log it.")
    token_type: Literal["aletheia.qr.dynamic"] = TOKEN_TYPE
    expires_at: datetime = Field(description="Authoritative UTC expiry, 30 seconds after issuance.")
    refresh_after: Literal[25] = REFRESH_AFTER


def check_claims(claims):
    if (set(claims) != CLAIMS or type(claims["v"]) is not int or claims["v"] != 1
            or claims["typ"] != TOKEN_TYPE or claims["aud"] != AUDIENCE
            or not isinstance(claims["iss"], str)
            or not isinstance(claims["sub"], str)
            or str(uuid.UUID(claims["sub"])) != claims["sub"]
            or not isinstance(claims["jti"], str)
            or not re.fullmatch(r"[A-Za-z0-9_-]{43}", claims["jti"])
            or any(type(claims[k]) is not int or claims[k] < 0 for k in ("iat", "nbf", "exp"))
            or claims["nbf"] != claims["iat"] or claims["exp"] - claims["iat"] != TTL):
        raise QRValidationError("Invalid dynamic QR claims")
    raw = base64.urlsafe_b64decode(claims["jti"] + "=")
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != claims["jti"]:
        raise QRValidationError("Invalid dynamic QR identifier")


class DynamicQRValidator:
    def __init__(self, settings: QRSettings, keys):
        self.settings, self.keys = settings, keys

    def validate(self, token: str) -> dict:
        try:
            if (not isinstance(token, str) or not 1 <= len(token) <= MAX_TOKEN_BYTES
                    or not re.fullmatch(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", token)):
                raise ValueError()
            parts = []
            for segment in token.split("."):
                raw = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
                if base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != segment:
                    raise ValueError()
                parts.append(raw)
            header, payload = (json.loads(p.decode("utf-8"), object_pairs_hook=_unique_object,
                                          parse_constant=_invalid_constant) for p in parts[:2])
            if (len(parts[2]) != 64 or not isinstance(header, dict) or not isinstance(payload, dict)
                    or set(header) != {"alg", "typ", "kid"}
                    or header["alg"] != "EdDSA" or header["typ"] != TOKEN_TYPE
                    or not isinstance(header["kid"], str)
                    or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", header["kid"])):
                raise ValueError()
            key = self.keys.verification_key("qr", header["kid"])
            if not isinstance(key, Ed25519PublicKey):
                raise ValueError()
            claims = jwt.decode(token, key, algorithms=["EdDSA"], issuer=self.settings.issuer,
                                audience=AUDIENCE, options={"require": sorted(CLAIMS), "strict_aud": True})
            check_claims(claims)
            return claims
        except KeyManagementError:
            raise
        except (jwt.PyJWTError, ValueError, TypeError, KeyError, AttributeError, OverflowError):
            raise QRValidationError("Invalid dynamic QR token") from None


class DynamicQRIssuer(DynamicQRValidator):
    async def issue(self, redis_client, user_id: uuid.UUID) -> DynamicIssueResponse:
        # Caller authenticates the active browser user. No unsigned subject input is accepted by the API.
        from qr.dynamic_state import register

        now = int(time.time())
        kid, key = self.keys.signing_key("qr")
        if not isinstance(key, Ed25519PrivateKey):
            raise KeyManagementError("An active QR Ed25519 key is required")
        claims = {"v": 1, "typ": TOKEN_TYPE, "iss": self.settings.issuer, "sub": str(user_id),
                  "aud": AUDIENCE, "jti": secrets.token_urlsafe(32), "iat": now, "nbf": now, "exp": now + TTL}
        check_claims(claims)
        token = jwt.encode(claims, key, algorithm="EdDSA", headers={"kid": kid, "typ": TOKEN_TYPE})
        await register(redis_client, claims)
        return DynamicIssueResponse(token=token, expires_at=datetime.fromtimestamp(claims["exp"], timezone.utc))
