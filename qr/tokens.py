import base64
import json
import os
import re
import secrets
import time
from dataclasses import dataclass

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from signing_keys import KeyManagementError, raw_key
from sso.jwt import JWTSettings, SigningKeys, VerificationKeys

TOKEN_TYPE = "argus-qr+jwt"
PURPOSE = "static_qr"
AUDIENCE = "argus-qr-verifier"
MAX_TTL = 3600  # Must not exceed signing_keys.RETENTION_SECONDS.
MAX_TOKEN_BYTES = 1024
CLAIMS = {"ver", "purpose", "iss", "aud", "cid", "iat", "exp"}


class QRValidationError(ValueError):
    pass


@dataclass(frozen=True)
class QRSettings:
    issuer: str
    ttl: int = 600

    def __post_init__(self):
        if (not isinstance(self.issuer, str) or not self.issuer.isascii()
                or not 1 <= len(self.issuer) <= 256
                or any(not 33 <= ord(c) <= 126 or c in '\\"' for c in self.issuer)):
            raise ValueError("QR issuer must be an ASCII URL of at most 256 characters; percent-encode special characters")
        JWTSettings(self.issuer, AUDIENCE)
        if type(self.ttl) is not int or not 1 <= self.ttl <= MAX_TTL:
            raise ValueError("QR lifetime must be between 1 and 3600 seconds")

    @classmethod
    def from_environment(cls, issuer):
        return cls(issuer, int(os.getenv("QR_TOKEN_TTL_SECONDS", "600")))


def check_compact_token(token: str):
    """Structural check for the image encoder; it does not establish trust."""
    if (not isinstance(token, str) or not 1 <= len(token) <= MAX_TOKEN_BYTES
            or not re.fullmatch(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", token)):
        raise QRValidationError("Invalid or oversized compact QR token")
    try:
        decoded = []
        for segment in token.split("."):
            raw = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
            if base64.urlsafe_b64encode(raw).rstrip(b"=").decode() != segment:
                raise ValueError()
            decoded.append(raw)
        if len(raw) != 64:
            raise ValueError()
        header, claims = (json.loads(part.decode("utf-8"), object_pairs_hook=_unique_object,
                                     parse_constant=_invalid_constant) for part in decoded[:2])
        if not isinstance(header, dict) or not isinstance(claims, dict):
            raise ValueError()
        if (set(header) != {"alg", "typ", "kid"} or header["alg"] != "EdDSA" or header["typ"] != TOKEN_TYPE
                or not isinstance(header["kid"], str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", header["kid"])):
            raise ValueError()
        check_claims(claims)
        return header
    except (jwt.PyJWTError, ValueError, TypeError, KeyError):
        raise QRValidationError("Invalid QR token header") from None


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError()
        result[key] = value
    return result


def _invalid_constant(value):
    raise ValueError()


def check_claims(claims):
    if (set(claims) != CLAIMS or type(claims["ver"]) is not int or claims["ver"] != 1
            or claims["purpose"] != PURPOSE or claims["aud"] != AUDIENCE
            or not isinstance(claims["iss"], str) or not claims["iss"].isascii()
            or not 1 <= len(claims["iss"]) <= 256
            or any(type(claims[k]) is not int or claims[k] < 0 for k in ("iat", "exp"))
            or not 0 < claims["exp"] - claims["iat"] <= MAX_TTL):
        raise QRValidationError("Invalid QR credential claims")
    raw_key(claims["cid"])


class QRValidator:
    def __init__(self, settings: QRSettings, keys: VerificationKeys):
        self.settings, self.keys = settings, keys

    def validate(self, token: str) -> dict:
        """Cryptographic validity only; online mapping/user checks are a separate boundary."""
        try:
            header = check_compact_token(token)
            key = self.keys.verification_key("qr", header["kid"])
            if not isinstance(key, Ed25519PublicKey):
                raise ValueError()
            claims = jwt.decode(token, key, algorithms=["EdDSA"], issuer=self.settings.issuer, audience=AUDIENCE,
                                options={"require": sorted(CLAIMS), "strict_aud": True})
            check_claims(claims)
            return claims
        except KeyManagementError:
            raise
        except (jwt.PyJWTError, ValueError, TypeError, KeyError, AttributeError, OverflowError):
            raise QRValidationError("Invalid static QR credential") from None


class QRIssuer(QRValidator):
    def __init__(self, settings: QRSettings, keys: SigningKeys):
        super().__init__(settings, keys)

    def issue(self) -> tuple[str, dict]:
        now = int(time.time())  # Before key snapshot, to respect rotation retention.
        kid, key = self.keys.signing_key("qr")
        if not isinstance(key, Ed25519PrivateKey):
            raise KeyManagementError("An active QR Ed25519 key is required")
        claims = {"ver": 1, "purpose": PURPOSE, "iss": self.settings.issuer, "aud": AUDIENCE,
                  "cid": secrets.token_urlsafe(32), "iat": now, "exp": now + self.settings.ttl}
        token = jwt.encode(claims, key, algorithm="EdDSA", headers={"kid": kid, "typ": TOKEN_TYPE})
        check_compact_token(token)
        return token, claims
