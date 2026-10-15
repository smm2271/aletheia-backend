import asyncio
import os
import stat
import subprocess
import sys
from dataclasses import replace

import jwt
import pytest

from signing_keys import FileKeyProvider, KeyManagementError, KeyRing, SigningKey, save_key_file
from sso.jwt import JWTIssuer, JWTValidationError, JWTValidator
from test_jwt import tokens


@pytest.fixture
def ring():
    return KeyRing([SigningKey.generate("sso"), SigningKey.generate("qr")])


def test_distinct_keys_roundtrip_and_qr_signatures(ring, tmp_path):
    path = tmp_path / "keys.json"
    save_key_file(path, ring, create=True)
    provider = FileKeyProvider(path)
    sso_id, sso = provider.signing_key("sso")
    qr_id, qr = provider.signing_key("qr")
    assert sso_id != qr_id
    assert sso.public_key().public_bytes_raw() != qr.public_key().public_bytes_raw()
    qr.public_key().verify(qr.sign(b"qr-test"), b"qr-test")
    assert provider.verification_key("sso", qr_id) is None
    assert provider.verification_key("qr", sso_id) is None
    assert provider.verification_key("sso", "unknown") is None
    assert "private" not in repr(ring.keys[0])
    if os.name != "nt":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    with pytest.raises(FileExistsError):
        save_key_file(path, ring, create=True)
    assert FileKeyProvider(path).signing_key("sso")[0] == sso_id


def test_jwks_interoperability_and_rotation(ring, tokens, tmp_path, monkeypatch):
    path = tmp_path / "keys.json"
    save_key_file(path, ring, create=True)
    provider = FileKeyProvider(path)
    _, settings, user, client, _, _ = tokens
    issuer, validator = JWTIssuer(settings, provider), JWTValidator(settings, provider)
    old = asyncio.run(issuer.issue(user, client, ["openid"]))
    jwks = provider.jwks()
    assert len(jwks["keys"]) == 1
    key = jwks["keys"][0]
    assert set(key) == {"kty", "crv", "x", "kid", "use", "alg"}
    public = jwt.PyJWK.from_dict(key).key
    assert jwt.decode(old.id_token, public, algorithms=["EdDSA"], audience="consumer")["sub"] == str(user.id)
    rotated = ring.rotate("sso")
    previous = next(k for k in rotated.keys if k.kid == key["kid"])
    assert previous.status == "verify_only" and previous.private is None
    with pytest.raises(KeyManagementError):
        rotated.retire(previous.kid)
    save_key_file(path, rotated)
    new = asyncio.run(issuer.issue(user, client, ["openid"]))
    assert jwt.get_unverified_header(new.id_token)["kid"] != key["kid"]
    assert len(provider.jwks()["keys"]) == 2
    validator.validate_id_token(old.id_token, client_id="consumer")
    validator.validate_id_token(new.id_token, client_id="consumer")
    monkeypatch.setattr("signing_keys.time.time", lambda: previous.retain_until + 1)
    save_key_file(path, rotated.retire(previous.kid))
    assert len(provider.jwks()["keys"]) == 1
    with pytest.raises(JWTValidationError):
        validator.validate_id_token(old.id_token, client_id="consumer")


@pytest.mark.parametrize("change", ["duplicate-id", "reuse-material", "mismatch", "active-without-private", "two-active", "purpose", "status"])
def test_invalid_key_configurations(ring, change):
    a, b = ring.keys
    cases = {
        "duplicate-id": [a, replace(b, kid=a.kid)],
        "reuse-material": [a, replace(a, kid=b.kid, purpose="qr")],
        "mismatch": [replace(a, private=b.private), b],
        "active-without-private": [replace(a, private=None), b],
        "two-active": [a, b, SigningKey.generate("sso")],
        "purpose": [replace(a, purpose="other"), b],
        "status": [replace(a, status="unknown"), b],
    }
    with pytest.raises(KeyManagementError):
        KeyRing(cases[change])


@pytest.mark.parametrize("content", ["bad-json", "{}", '{"version":2,"keys":[]}', '{"version":1,"keys":[{}]}'])
def test_bad_secret_file_is_sanitized(tmp_path, content):
    path = tmp_path / "keys.json"
    path.write_text(content)
    path.chmod(0o600)
    with pytest.raises(KeyManagementError, match="Unable to load protected"):
        FileKeyProvider(path)


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode permissions; Windows uses ACL provisioning")
def test_permissive_secret_file_rejected(ring, tmp_path):
    path = tmp_path / "keys.json"
    save_key_file(path, ring, create=True)
    path.chmod(0o644)
    with pytest.raises(KeyManagementError):
        FileKeyProvider(path)


def test_operator_cli_preserves_old_public_keys_and_never_prints_secrets(tmp_path):
    path = tmp_path / "keys.json"
    result = subprocess.run([sys.executable, "-m", "signing_keys", "generate", str(path)], capture_output=True, text=True)
    assert result.returncode == 0 and result.stdout.strip() == "Key configuration saved"
    provider = FileKeyProvider(path)
    old_id, _ = provider.signing_key("sso")
    result = subprocess.run([sys.executable, "-m", "signing_keys", "rotate", str(path), "--purpose", "sso"], capture_output=True, text=True)
    assert result.returncode == 0 and result.stdout.strip() == "Key configuration saved"
    assert provider.signing_key("sso")[0] != old_id
    assert provider.verification_key("sso", old_id) is not None
    result = subprocess.run([sys.executable, "-m", "signing_keys", "retire", str(path), "--kid", old_id], capture_output=True, text=True)
    assert result.returncode == 1 and "retention policy" in result.stderr
    assert "private_key" not in result.stdout + result.stderr
