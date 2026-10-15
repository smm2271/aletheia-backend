"""Purpose-separated Ed25519 keys, with an atomic secret-file adapter and CLI."""

import argparse
import base64
import csv
import json
import os
import re
import stat
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass, field, replace
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

PURPOSES = {"sso", "qr"}
STATUSES = {"active", "verify_only", "retired"}
# JWTSettings caps both token lifetimes at one hour. Retain public keys at least this long.
RETENTION_SECONDS = 3600


class KeyManagementError(ValueError):
    pass


def b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def raw_key(value: str) -> bytes:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", value):
        raise ValueError()
    raw = base64.urlsafe_b64decode(value + "=")
    if b64(raw) != value:
        raise ValueError()
    return raw


@dataclass(frozen=True)
class SigningKey:
    kid: str
    purpose: str
    status: str
    created_at: int
    public: Ed25519PublicKey
    private: Ed25519PrivateKey | None = field(default=None, repr=False)
    retain_until: int | None = None

    @classmethod
    def generate(cls, purpose: str):
        if purpose not in PURPOSES:
            raise KeyManagementError("Unknown key purpose")
        private = Ed25519PrivateKey.generate()
        return cls(str(uuid.uuid4()), purpose, "active", int(time.time()), private.public_key(), private)

    def jwk(self) -> dict:
        return {"kty": "OKP", "crv": "Ed25519", "x": b64(self.public.public_bytes_raw()),
                "kid": self.kid, "use": "sig", "alg": "EdDSA"}


class KeyRing:
    """A snapshot supplied by a secret manager or the secret-file adapter."""

    def __init__(self, keys: list[SigningKey]):
        ids, materials = set(), set()
        for key in keys:
            material = key.public.public_bytes_raw()
            if (not isinstance(key.kid, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", key.kid)
                    or key.kid in ids or material in materials or key.purpose not in PURPOSES
                    or key.status not in STATUSES or type(key.created_at) is not int or key.created_at < 0
                    or (key.status == "active" and key.private is None)
                    or (key.status != "active" and key.private is not None)
                    or (key.status == "verify_only" and (type(key.retain_until) is not int or key.retain_until < key.created_at))
                    or (key.private and key.private.public_key().public_bytes_raw() != material)):
                raise KeyManagementError("Invalid or reused signing key")
            ids.add(key.kid)
            materials.add(material)
        if any(sum(k.status == "active" and k.purpose == p for k in keys) != 1 for p in PURPOSES):
            raise KeyManagementError("Exactly one active key per purpose is required")
        self.keys = tuple(keys)

    def signing_key(self, purpose: str) -> tuple[str, Ed25519PrivateKey]:
        for key in self.keys:
            if key.purpose == purpose and key.status == "active":
                return key.kid, key.private
        raise KeyManagementError("No active signing key for purpose")

    def verification_key(self, purpose: str, kid: str) -> Ed25519PublicKey | None:
        return next((k.public for k in self.keys if k.kid == kid and k.purpose == purpose and k.status != "retired"), None)

    def jwks(self) -> dict:
        # OIDC only distributes SSO keys; QR has a separate trust boundary.
        return {"keys": [k.jwk() for k in self.keys if k.purpose == "sso" and k.status != "retired"]}

    def rotate(self, purpose: str):
        self.signing_key(purpose)  # Reject unsupported purposes.
        now = int(time.time())
        keys = [replace(k, status="verify_only", private=None, retain_until=now + RETENTION_SECONDS)
                if k.purpose == purpose and k.status == "active" else k for k in self.keys]
        return KeyRing([*keys, SigningKey.generate(purpose)])

    def retire(self, kid: str):
        key = next((k for k in self.keys if k.kid == kid), None)
        if key is None or key.status != "verify_only" or int(time.time()) < key.retain_until:
            raise KeyManagementError("Only verify-only keys past their retention deadline may be retired")
        return KeyRing([replace(k, status="retired") if k.kid == kid else k for k in self.keys])

    def secret_document(self) -> dict:
        return {"version": 1, "keys": [
            {"kid": k.kid, "purpose": k.purpose, "status": k.status, "created_at": k.created_at,
             "public_key": b64(k.public.public_bytes_raw()), "retain_until": k.retain_until,
             **({"private_key": b64(k.private.private_bytes_raw())} if k.private else {})}
            for k in self.keys
        ]}

    @classmethod
    def from_document(cls, document: dict):
        try:
            if document["version"] != 1 or not isinstance(document["keys"], list):
                raise ValueError()
            return cls([SigningKey(
                kid=k["kid"], purpose=k["purpose"], status=k["status"], created_at=k["created_at"],
                public=Ed25519PublicKey.from_public_bytes(raw_key(k["public_key"])),
                private=Ed25519PrivateKey.from_private_bytes(raw_key(k["private_key"])) if "private_key" in k else None,
                retain_until=k.get("retain_until"),
            ) for k in document["keys"]])
        except (ValueError, TypeError, KeyError, AttributeError):
            raise KeyManagementError("Invalid signing key configuration") from None


class FileKeyProvider:
    """Reload each snapshot; atomic replacement makes rotation visible to every worker."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.snapshot()

    def snapshot(self) -> KeyRing:
        try:
            with self.path.open("rb") as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or (os.name != "nt" and info.st_mode & 0o077):
                    raise ValueError()
                raw = stream.read(262145)
                if len(raw) > 262144:
                    raise ValueError()
            return KeyRing.from_document(json.loads(raw))
        except (OSError, ValueError, TypeError):
            raise KeyManagementError("Unable to load protected signing key configuration") from None

    def signing_key(self, purpose):
        return self.snapshot().signing_key(purpose)

    def verification_key(self, purpose, kid):
        return self.snapshot().verification_key(purpose, kid)

    def jwks(self):
        return self.snapshot().jwks()


def save_key_file(path: Path, ring: KeyRing, *, create: bool = False):
    """Run key administration with one writer; file replacement is atomic for readers."""
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    data = json.dumps(ring.secret_document()).encode("utf-8")
    if create:
        # Exclusive creation never overwrites existing keys.
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            protect_windows_file(path)
            stream.write(data)
        return
    descriptor, temporary = tempfile.mkstemp(prefix=".keys-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            protect_windows_file(Path(temporary))
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def protect_windows_file(path: Path):
    if os.name == "nt":
        result = subprocess.check_output(["whoami", "/user", "/fo", "csv", "/nh"], text=True)
        sid = next(csv.reader(result.splitlines()))[1]
        subprocess.run(["icacls", str(path), "/inheritance:r", "/grant:r", f"*{sid}:(F)"],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def main():
    parser = argparse.ArgumentParser(description="Administer Ed25519 secret files; never prints key material")
    parser.add_argument("command", choices=["generate", "rotate", "retire"])
    parser.add_argument("path", type=Path)
    parser.add_argument("--purpose", choices=sorted(PURPOSES))
    parser.add_argument("--kid")
    args = parser.parse_args()
    try:
        if args.command == "generate":
            ring = KeyRing([SigningKey.generate("sso"), SigningKey.generate("qr")])
        else:
            ring = FileKeyProvider(args.path).snapshot()
            ring = ring.rotate(args.purpose) if args.command == "rotate" else ring.retire(args.kid)
        save_key_file(args.path, ring, create=args.command == "generate")
    except (OSError, KeyManagementError, subprocess.SubprocessError):
        parser.exit(1, "Key administration failed; check configuration, permissions and retention policy\n")
    print("Key configuration saved")


if __name__ == "__main__":
    main()
