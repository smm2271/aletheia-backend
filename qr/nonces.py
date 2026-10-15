"""Bounded request deduplication; static QR copies require a separate defense."""

import base64
import hashlib
import os
import re
import secrets
import time
from dataclasses import dataclass

NONCE_NAMESPACE = "qr-static-verify:v1"
DEFAULT_NONCE_TTL = 300
MAX_TTL = 600
MAX_NONCE_LENGTH = 64


class NonceValidationError(ValueError):
    """Invalid or expired nonce; messages never contain supplied credentials."""


class NonceReplayError(NonceValidationError):
    """This client has already consumed this nonce."""


class NonceStoreUnavailable(RuntimeError):
    """Consumption could not be confirmed. The caller must fail closed."""


@dataclass(frozen=True)
class NonceSettings:
    ttl: int = DEFAULT_NONCE_TTL

    def __post_init__(self):
        if type(self.ttl) is not int or not 1 <= self.ttl <= MAX_TTL:
            raise ValueError("Nonce lifetime must be between 1 and 600 seconds")

    @classmethod
    def from_environment(cls):
        try:
            return cls(int(os.getenv("QR_NONCE_TTL_SECONDS", str(DEFAULT_NONCE_TTL))))
        except (ValueError, TypeError):
            raise ValueError("Invalid nonce lifetime configuration") from None


def generate_nonce(now=None) -> str:
    """Generate a timestamped 256-bit nonce on a trusted request client/server."""
    timestamp = int(time.time()) if now is None else now
    if type(timestamp) is not int or not 0 <= timestamp <= 99999999999999999:
        raise NonceValidationError("Invalid nonce timestamp")
    return f"v1.{timestamp}.{secrets.token_urlsafe(32)}"


def _issued_at(nonce):
    if not isinstance(nonce, str) or not 1 <= len(nonce) <= MAX_NONCE_LENGTH:
        raise NonceValidationError("Invalid nonce format")
    match = re.fullmatch(r"v1\.(0|[1-9][0-9]{0,16})\.([A-Za-z0-9_-]{43})", nonce)
    if match is None:
        raise NonceValidationError("Invalid nonce format")
    encoded = match[2]
    raw = base64.urlsafe_b64decode(encoded + "=")
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != encoded:
        raise NonceValidationError("Invalid nonce format")
    return int(match[1])


async def consume_nonce(redis_client, *, client_id, nonce, settings=None, namespace=NONCE_NAMESPACE) -> None:
    """Atomically reserve the client-scoped nonce until its embedded deadline."""
    settings = NonceSettings() if settings is None else settings
    if not isinstance(settings, NonceSettings):
        raise NonceValidationError("Invalid nonce settings")
    if (not isinstance(client_id, str) or not 1 <= len(client_id) <= 256
            or client_id != client_id.strip()
            or not isinstance(namespace, str)
            or not re.fullmatch(r"[A-Za-z0-9:._-]{1,64}", namespace)):
        raise NonceValidationError("Invalid nonce scope")
    issued_at = _issued_at(nonce)
    now = int(time.time())
    if not now - settings.ttl < issued_at <= now:
        raise NonceValidationError("Expired or future nonce")
    remaining = issued_at + settings.ttl - now
    try:
        client_digest = hashlib.sha256(client_id.encode("utf-8")).hexdigest()
    except UnicodeEncodeError:
        raise NonceValidationError("Invalid nonce scope") from None
    nonce_digest = hashlib.sha256(nonce.encode("ascii")).hexdigest()
    key = f"{namespace}:{client_digest}:{nonce_digest}"
    try:
        result = await redis_client.set(key, "1", nx=True, ex=remaining)
    except Exception:
        # A lost response can follow a successful SET. Never retry acceptance or
        # expose Redis exception text (which can contain connection secrets).
        raise NonceStoreUnavailable("Nonce store unavailable") from None
    if result is None:
        raise NonceReplayError("Nonce already consumed")
    if result is not True:
        raise NonceStoreUnavailable("Nonce consumption could not be confirmed")
