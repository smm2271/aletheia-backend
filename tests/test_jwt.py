import asyncio
import base64
import json
import time
import uuid
from dataclasses import replace

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey

from models import SSOClient, User
from sso.jwt import JWTIssuer, JWTSettings, JWTValidationError, JWTValidator


class MemoryKeys:
    """Test-only key provider. No production keys or files are created."""

    def __init__(self):
        self.kid = "sso-1"
        self.private = Ed25519PrivateKey.generate()
        self.public = {self.kid: self.private.public_key()}

    def signing_key(self, purpose):
        assert purpose == "sso"
        return self.kid, self.private

    def verification_key(self, purpose, kid):
        assert purpose == "sso"
        return self.public.get(kid)


@pytest.fixture
def tokens():
    keys = MemoryKeys()
    settings = JWTSettings("https://argus.example", "https://api.example", access_ttl=300, id_ttl=120)
    user = User(id=uuid.uuid4(), email="private@example.edu", username="Private Name")
    client = SSOClient(client_id="consumer", enabled=True, allowed_scopes=["openid", "profile"])
    issuer = JWTIssuer(settings, keys)
    response = asyncio.run(issuer.issue(user, client, ["openid", "profile"], "nonce + 中文"))
    return keys, settings, user, client, response, JWTValidator(settings, keys)


def test_issuance_and_public_key_verification(tokens):
    keys, settings, user, client, response, validator = tokens
    # Verify using only the public key, independently from our validation service.
    claims = jwt.decode(response.id_token, keys.private.public_key(), algorithms=["EdDSA"],
                        issuer=settings.issuer, audience=client.client_id)
    assert claims == validator.validate_id_token(response.id_token, client_id=client.client_id, nonce="nonce + 中文")
    assert claims["sub"] == str(user.id)
    assert claims["exp"] - claims["iat"] == 120
    assert set(claims) == {"iss", "sub", "aud", "iat", "exp", "nonce", "token_use"}
    assert jwt.get_unverified_header(response.id_token) == {"alg": "EdDSA", "kid": "sso-1", "typ": "JWT"}
    access = validator.validate_access_token(response.access_token, audience=settings.access_audience, required_scopes=("profile",))
    assert access["aud"] == settings.access_audience
    assert access["client_id"] == client.client_id
    assert set(access) == {"iss", "sub", "aud", "iat", "exp", "token_use", "scope", "client_id", "jti"}
    assert response.expires_in == access["exp"] - access["iat"] == 300
    assert response.token_type == "Bearer" and response.scope == "openid profile"


def resign(tokens, *, changes=None, remove=None, headers=None, key=None):
    keys, _, _, _, response, _ = tokens
    claims = jwt.decode(response.access_token, options={"verify_signature": False})
    claims.update(changes or {})
    if remove:
        del claims[remove]
    # Sign raw JOSE input so malformed headers are not sanitized by PyJWT's encoder.
    def b64(value):
        return base64.urlsafe_b64encode(value).rstrip(b"=")
    header = {"alg": "EdDSA", "kid": keys.kid, "typ": "at+jwt", **(headers or {})}
    message = b64(json.dumps(header).encode()) + b"." + b64(json.dumps(claims).encode())
    return (message + b"." + b64((key or keys.private).sign(message))).decode()


@pytest.mark.parametrize("changes", [
    {"iss": "https://evil.example"}, {"aud": "other-api"}, {"aud": ["https://api.example", "other"]},
    {"exp": int(time.time()) - 10}, {"iat": int(time.time()) + 120},
    {"exp": int(time.time()) + 7200}, {"iat": "123"}, {"exp": True}, {"exp": float("inf")},
    {"sub": "not-a-uuid"}, {"token_use": "id_token"}, {"scope": ["profile"]},
    {"scope": "profile  openid"}, {"scope": "profile profile"}, {"scope": ""},
    {"client_id": ""}, {"jti": 42},
])
def test_invalid_claims_rejected(tokens, changes):
    with pytest.raises(JWTValidationError):
        tokens[-1].validate_access_token(resign(tokens, changes=changes), audience=tokens[1].access_audience)


@pytest.mark.parametrize("claim", ["iss", "sub", "aud", "iat", "exp", "token_use", "scope", "client_id", "jti"])
def test_required_claims(tokens, claim):
    with pytest.raises(JWTValidationError):
        tokens[-1].validate_access_token(resign(tokens, remove=claim), audience=tokens[1].access_audience)


@pytest.mark.parametrize("headers", [{"kid": "unknown"}, {"kid": ""}, {"kid": 1}, {"typ": "JWT"},
                                    {"crit": ["custom"]}, {"b64": True}])
def test_invalid_headers(tokens, headers):
    with pytest.raises(JWTValidationError):
        tokens[-1].validate_access_token(resign(tokens, headers=headers), audience=tokens[1].access_audience)


def test_signature_tampering_and_algorithms(tokens):
    _, settings, _, _, response, validator = tokens
    none_token = jwt.encode({"sub": str(uuid.uuid4())}, key=None, algorithm="none", headers={"kid": "sso-1", "typ": "at+jwt"})
    hs_token = jwt.encode({"sub": str(uuid.uuid4())}, "attacker-secret" * 4, algorithm="HS256", headers={"kid": "sso-1", "typ": "at+jwt"})
    parts = response.access_token.split(".")
    parts[1] = parts[1][:-1] + ("A" if parts[1][-1] != "A" else "B")
    for token in (none_token, hs_token, resign(tokens, key=Ed25519PrivateKey.generate()), ".".join(parts), "broken", "", None):
        with pytest.raises(JWTValidationError):
            validator.validate_access_token(token, audience=settings.access_audience)


def test_token_type_isolation_even_with_same_audience(tokens):
    keys, settings, user, client, _, _ = tokens
    settings = replace(settings, access_audience=client.client_id)
    response = asyncio.run(JWTIssuer(settings, keys).issue(user, client, ["openid"]))
    validator = JWTValidator(settings, keys)
    with pytest.raises(JWTValidationError):
        validator.validate_access_token(response.id_token, audience=client.client_id)
    with pytest.raises(JWTValidationError):
        validator.validate_id_token(response.access_token, client_id=client.client_id)


def test_nonce_audience_and_scope_enforcement(tokens):
    _, settings, _, _, response, validator = tokens
    for nonce in ("wrong", ""):
        with pytest.raises(JWTValidationError):
            validator.validate_id_token(response.id_token, client_id="consumer", nonce=nonce)
    with pytest.raises(JWTValidationError):
        validator.validate_id_token(response.id_token, client_id="other-client")
    with pytest.raises(JWTValidationError):
        validator.validate_access_token(response.access_token, audience="other-resource")
    with pytest.raises(JWTValidationError):
        validator.validate_access_token(response.access_token, audience=settings.access_audience, required_scopes=("admin",))


def test_openid_and_optional_nonce(tokens):
    keys, settings, user, client, _, validator = tokens
    issuer = JWTIssuer(settings, keys)
    response = asyncio.run(issuer.issue(user, client, ["profile"], "ignored-for-access"))
    assert response.id_token is None
    response = asyncio.run(issuer.issue(user, client, ["openid"]))
    assert "nonce" not in validator.validate_id_token(response.id_token, client_id="consumer")
    with pytest.raises(JWTValidationError):
        validator.validate_id_token(response.id_token, client_id="consumer", nonce="expected")


def test_key_rotation_and_retirement(tokens):
    keys, settings, user, client, old, validator = tokens
    keys.kid, keys.private = "sso-2", Ed25519PrivateKey.generate()
    keys.public[keys.kid] = keys.private.public_key()
    new = asyncio.run(JWTIssuer(settings, keys).issue(user, client, ["openid"]))
    for response in (old, new):
        validator.validate_access_token(response.access_token, audience=settings.access_audience)
    del keys.public["sso-1"]
    with pytest.raises(JWTValidationError):
        validator.validate_access_token(old.access_token, audience=settings.access_audience)


def test_wrong_curve_rejected(tokens):
    keys, settings, user, client, response, validator = tokens
    keys.private = Ed448PrivateKey.generate()
    with pytest.raises(ValueError):
        asyncio.run(JWTIssuer(settings, keys).issue(user, client, ["openid"]))
    keys.public["sso-1"] = keys.private.public_key()
    with pytest.raises(JWTValidationError):
        validator.validate_access_token(response.access_token, audience=settings.access_audience)


@pytest.mark.parametrize("scopes", [[], ["admin"], ["openid", "openid"]])
def test_issuer_rejects_invalid_grant(tokens, scopes):
    keys, settings, user, client, _, _ = tokens
    with pytest.raises(ValueError):
        asyncio.run(JWTIssuer(settings, keys).issue(user, client, scopes))


@pytest.mark.parametrize("changes", [
    {"issuer": "http://argus.example"}, {"issuer": "https://argus.example?query"},
    {"issuer": "https://argus.example#"}, {"issuer": "https://u:p@argus.example"},
    {"access_audience": ""}, {"access_ttl": 0}, {"id_ttl": 3601}, {"access_ttl": True},
])
def test_invalid_configuration(tokens, changes):
    with pytest.raises(ValueError):
        replace(tokens[1], **changes)
