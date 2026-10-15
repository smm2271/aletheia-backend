import base64
import json
import time
from dataclasses import replace
from io import BytesIO

import jwt
import pytest
import zxingcpp
from PIL import Image

from qr.encoding import encode_png
from qr.tokens import AUDIENCE, CLAIMS, MAX_TOKEN_BYTES, QRIssuer, QRSettings, QRValidationError, QRValidator, TOKEN_TYPE, check_compact_token
from signing_keys import KeyManagementError, KeyRing, SigningKey
from sso.jwt import JWTSettings, JWTValidationError, JWTValidator


@pytest.fixture
def qr_token():
    keys = KeyRing([SigningKey.generate("sso"), SigningKey.generate("qr")])
    settings = QRSettings("https://argus.example")
    issuer = QRIssuer(settings, keys)
    token, claims = issuer.issue()
    return keys, settings, issuer, token, claims


def sign(qr_token, changes=None, headers=None, remove=None, purpose="qr", key=None):
    keys, _, _, _, original = qr_token
    kid, private = keys.signing_key(purpose)
    claims = {**original, **(changes or {})}
    if remove:
        del claims[remove]
    header = {"alg": "EdDSA", "kid": kid, "typ": TOKEN_TYPE, **(headers or {})}
    def b64(data):
        return base64.urlsafe_b64encode(data).rstrip(b"=")
    data = b64(json.dumps(header).encode()) + b"." + b64(json.dumps(claims).encode())
    return (data + b"." + b64((key or private).sign(data))).decode()


def test_qr_key_signature_claims_and_minimal_disclosure(qr_token):
    keys, settings, issuer, token, claims = qr_token
    assert issuer.validate(token) == claims
    kid, key = keys.signing_key("qr")
    assert jwt.get_unverified_header(token) == {"alg": "EdDSA", "typ": TOKEN_TYPE, "kid": kid}
    assert jwt.decode(token, key.public_key(), algorithms=["EdDSA"], issuer=settings.issuer, audience=AUDIENCE) == claims
    assert set(claims) == CLAIMS
    assert len(claims["cid"]) == 43 and "sub" not in claims
    assert claims["exp"] - claims["iat"] == 600
    assert issuer.issue()[1]["cid"] != claims["cid"]
    assert len(token) <= MAX_TOKEN_BYTES


@pytest.mark.parametrize("changes", [
    {"ver": 2}, {"ver": True}, {"purpose": "access_token"}, {"aud": "api"},
    {"iss": "https://another.example"}, {"cid": "user-uuid"}, {"cid": "A" * 42},
    {"iat": int(time.time()) + 3600}, {"exp": 0}, {"exp": int(time.time()) + 7200},
    {"iat": "123"}, {"exp": True}, {"exp": float("inf")},
    {"email": "private@example.edu"},
])
def test_invalid_claims_rejected(qr_token, changes):
    with pytest.raises(QRValidationError):
        qr_token[2].validate(sign(qr_token, changes))


@pytest.mark.parametrize("claim", sorted(CLAIMS))
def test_required_claims(qr_token, claim):
    with pytest.raises(QRValidationError):
        qr_token[2].validate(sign(qr_token, remove=claim))


@pytest.mark.parametrize("headers", [
    {"kid": "unknown"}, {"kid": ""}, {"kid": 1}, {"typ": "JWT"},
    {"alg": "none"}, {"alg": "HS256"}, {"crit": ["x"]}, {"jwk": {}},
    {"jku": "https://evil.example/keys"}, {"b64": False},
])
def test_invalid_headers_rejected(qr_token, headers):
    with pytest.raises(QRValidationError):
        qr_token[2].validate(sign(qr_token, headers=headers))


def test_tampering_unknown_keys_and_sso_isolation(qr_token):
    keys, settings, issuer, token, _ = qr_token
    for bad in (sign(qr_token, key=SigningKey.generate("qr").private), sign(qr_token, purpose="sso"),
                token.replace(".", ".A", 1), "broken", "", None):
        with pytest.raises(QRValidationError):
            issuer.validate(bad)
    validator = JWTValidator(JWTSettings(settings.issuer, AUDIENCE), keys)
    with pytest.raises(JWTValidationError):
        validator.validate_access_token(token, audience=AUDIENCE)
    with pytest.raises(JWTValidationError):
        validator.validate_id_token(token, client_id=AUDIENCE)


def test_rotation_keeps_existing_credentials_valid(qr_token):
    keys, settings, _, token, _ = qr_token
    rotated = keys.rotate("qr")
    assert QRValidator(settings, rotated).validate(token)
    # Removing the old QR public key must fail even when an SSO key has a matching kid.
    old_id = jwt.get_unverified_header(token)["kid"]
    retired = KeyRing([replace(k, status="retired") if k.kid == old_id else k for k in rotated.keys])
    with pytest.raises(QRValidationError):
        QRValidator(settings, retired).validate(token)


def test_standard_decoder_roundtrip(qr_token):
    token = qr_token[3]
    png = encode_png(token)
    assert png.startswith(b"\x89PNG\r\n\x1a\n")
    decoded = zxingcpp.read_barcode(Image.open(BytesIO(png)))
    assert decoded is not None and decoded.format == zxingcpp.BarcodeFormat.QRCode
    assert decoded.text == token
    assert qr_token[2].validate(decoded.text) == qr_token[4]


@pytest.mark.parametrize("value", ["", "not-a-token", "https://example.edu?user_id=1", "個人資料", "A" * 1025, None])
def test_encoder_rejects_invalid_content(value):
    with pytest.raises(QRValidationError):
        encode_png(value)


def test_encoder_has_capacity_limit_and_is_not_a_signature_verifier(qr_token):
    with pytest.raises(QRValidationError):
        encode_png(sign(qr_token, headers={"kid": "A" * 1000}))
    # An image encoder has no trusted key set; a structurally valid forgery still needs verification.
    forged = sign(qr_token, key=SigningKey.generate("qr").private)
    assert encode_png(forged)
    with pytest.raises(QRValidationError):
        qr_token[2].validate(forged)


@pytest.mark.parametrize("ttl", [0, 3601, True, "600"])
def test_invalid_settings(ttl):
    with pytest.raises(ValueError):
        QRSettings("https://argus.example", ttl)


@pytest.mark.parametrize("issuer", [None, 123, "https://例子.example", "https://example/" + "a" * 256,
                                  'https://example/"', "https://example/\\", "https://example/" + chr(127)])
def test_issuer_capacity_rejected_at_configuration(issuer):
    with pytest.raises(ValueError):
        QRSettings(issuer)


def test_largest_supported_issuer_key_id_and_lifetime_roundtrip(qr_token):
    keys = KeyRing([replace(k, kid="K" * 128) if k.purpose == "qr" else k for k in qr_token[0].keys])
    issuer_url = "https://argus.example/" + "a" * (256 - len("https://argus.example/"))
    issuer = QRIssuer(QRSettings(issuer_url, ttl=3600), keys)
    token, claims = issuer.issue()
    assert len(token.encode("ascii")) <= MAX_TOKEN_BYTES
    decoded = zxingcpp.read_barcode(Image.open(BytesIO(encode_png(token))))
    assert decoded is not None and decoded.text == token
    assert issuer.validate(decoded.text) == claims


@pytest.mark.parametrize("header,payload", [
    (b'{"alg":"none","alg":"EdDSA","typ":"argus-qr+jwt","kid":"x"}', b'{}'),
    (b'{"alg":"EdDSA","typ":"argus-qr+jwt","kid":"x"}', b'{"exp":1,"exp":2}'),
    (b'{"alg":"EdDSA","typ":"argus-qr+jwt","kid":"x"}', b'{"exp":NaN}'),
    (b'[]', b'{}'), (b'{}', b'[]'), (b'{}', b'null'),
    (b'\xff', b'{}'),
])
def test_ambiguous_or_malformed_json_rejected(header, payload):
    token = ".".join(base64.urlsafe_b64encode(part).rstrip(b"=").decode("ascii")
                     for part in (header, payload, b"x" * 64))
    with pytest.raises(QRValidationError):
        check_compact_token(token)
    with pytest.raises(QRValidationError):
        encode_png(token)


@pytest.mark.parametrize("segment,member", [(0, '"alg":"EdDSA",'), (1, '"ver":1,')])
def test_duplicate_members_in_otherwise_valid_token_are_rejected(qr_token, segment, member):
    parts = qr_token[3].split(".")
    raw = base64.urlsafe_b64decode(parts[segment] + "=" * (-len(parts[segment]) % 4))
    duplicate = b"{" + member.encode("ascii") + raw[1:]
    parts[segment] = base64.urlsafe_b64encode(duplicate).rstrip(b"=").decode("ascii")
    # The structural boundary itself rejects ambiguity, independently of the signature.
    with pytest.raises(QRValidationError):
        check_compact_token(".".join(parts))


def test_noncanonical_base64url_is_rejected(qr_token):
    token = qr_token[3]
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    # The final signature character contains four padding bits. Changing only
    # those bits preserves decoded signature bytes but violates canonical form.
    altered = token[:-1] + alphabet[alphabet.index(token[-1]) + 1]
    assert base64.urlsafe_b64decode(altered.split(".")[-1] + "==") == base64.urlsafe_b64decode(token.split(".")[-1] + "==")
    with pytest.raises(QRValidationError):
        check_compact_token(altered)


def test_expired_valid_signature_is_rejected(qr_token):
    now = int(time.time())
    with pytest.raises(QRValidationError):
        qr_token[2].validate(sign(qr_token, {"iat": now - 600, "exp": now - 1}))


def test_key_provider_failure_stays_an_operational_error(qr_token):
    class UnavailableProvider:
        def verification_key(self, purpose, kid):
            raise KeyManagementError("Unavailable keys")

    with pytest.raises(KeyManagementError):
        QRValidator(qr_token[1], UnavailableProvider()).validate(qr_token[3])
