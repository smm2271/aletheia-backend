"""W10 contract and real Redis/PostgreSQL integration acceptance."""

import asyncio
import base64
import json
import os
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from unittest.mock import AsyncMock

import jwt
import pytest
from redis.asyncio import Redis
from redis.exceptions import ConnectionError, TimeoutError
from sqlalchemy.orm import Session

from main import app
from models import SSOClient, User
from qr.dynamic_state import DynamicStoreUnavailable, consume, register as register_state, revoke, state_key
from qr.dynamic_tokens import AUDIENCE, CLAIMS, TOKEN_TYPE, DynamicQRIssuer
from qr.tokens import QRIssuer, QRSettings, QRValidationError
from signing_keys import KeyManagementError, KeyRing, SigningKey
from test_authorization import auth_flow, register
from test_browser_session import login
from test_google_oauth import callback, flow, signing_key, start
from test_oidc_integration import oidc_flow
from test_qr_verification_flow import exchange

ROOT = "/api/v1/qr/dynamic"
SCOPE = "qr:dynamic:verify"
ORIGIN = {"Origin": "http://localhost"}


@pytest.fixture
def issuer():
    return DynamicQRIssuer(QRSettings("https://argus.example"),
                           KeyRing([SigningKey.generate("qr"), SigningKey.generate("sso")]))


def issue_local(issuer):
    client = AsyncMock()
    client.eval.return_value = 1
    response = asyncio.run(issuer.issue(client, uuid.uuid4()))
    return response.token, issuer.validate(response.token)


def sign(issuer, claims, *, headers=None, purpose="qr", key=None):
    kid, private = issuer.keys.signing_key(purpose)
    return jwt.encode(claims, key or private, algorithm="EdDSA",
                      headers={"typ": TOKEN_TYPE, "kid": kid, **(headers or {})})


def test_schema_entropy_key_isolation_and_static_separation(issuer):
    token, claims = issue_local(issuer)
    assert set(claims) == CLAIMS
    assert claims["exp"] - claims["iat"] == 30 and claims["nbf"] == claims["iat"]
    assert len(base64.urlsafe_b64decode(claims["jti"] + "=")) == 32
    assert issue_local(issuer)[1]["jti"] != claims["jti"]
    static = QRIssuer(issuer.settings, issuer.keys)
    for validator, wrong_token in ((static, token), (issuer, static.issue()[0]),
                                    (issuer, sign(issuer, claims, purpose="sso"))):
        with pytest.raises(QRValidationError):
            validator.validate(wrong_token)


@pytest.mark.parametrize("change", [
    {"v": True}, {"v": 2}, {"typ": "argus-qr+jwt"}, {"aud": "wrong"}, {"aud": [AUDIENCE]},
    {"iss": "https://wrong.example"}, {"sub": "not-a-uuid"}, {"sub": None},
    {"jti": "A" * 42}, {"jti": "A" * 42 + "B"}, {"iat": True}, {"exp": 0},
    {"nbf": int(time.time()) + 600}, {"email": "private@example.edu"},
])
def test_claim_rejections(issuer, change):
    _, claims = issue_local(issuer)
    with pytest.raises(QRValidationError):
        issuer.validate(sign(issuer, {**claims, **change}))


@pytest.mark.parametrize("claim", sorted(CLAIMS))
def test_required_claims(issuer, claim):
    _, claims = issue_local(issuer)
    del claims[claim]
    with pytest.raises(QRValidationError):
        issuer.validate(sign(issuer, claims))


@pytest.mark.parametrize("header", [{"typ": "JWT"}, {"kid": "unknown"}, {"kid": ""},
                                      {"jku": "https://evil.example"}, {"crit": ["x"]}])
def test_header_rejections(issuer, header):
    _, claims = issue_local(issuer)
    with pytest.raises(QRValidationError):
        issuer.validate(sign(issuer, claims, headers=header))


@pytest.mark.parametrize("token", [None, "", "bad", "a.b.c", "A" * 2049, "é.é.é"])
def test_malformed_token(issuer, token):
    with pytest.raises(QRValidationError):
        issuer.validate(token)


def test_forgery_and_payload_tampering(issuer):
    token, claims = issue_local(issuer)
    forged = sign(issuer, claims, key=SigningKey.generate("qr").private)
    pieces = token.split(".")
    claims["sub"] = str(uuid.uuid4())
    pieces[1] = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    for value in (forged, ".".join(pieces)):
        with pytest.raises(QRValidationError):
            issuer.validate(value)


@pytest.mark.parametrize("age,valid", [(0, True), (25, True), (29, True), (30, False), (31, False), (-1, False)])
def test_time_boundaries(issuer, age, valid):
    _, claims = issue_local(issuer)
    now = int(time.time())
    claims.update(iat=now - age, nbf=now - age, exp=now - age + 30)
    if valid:
        assert issuer.validate(sign(issuer, claims)) == claims
    else:
        with pytest.raises(QRValidationError):
            issuer.validate(sign(issuer, claims))


@pytest.mark.parametrize("operation", ["issue", "consume", "revoke"])
@pytest.mark.parametrize("failure", [ConnectionError, TimeoutError, RuntimeError])
def test_store_failures_are_sanitized(issuer, operation, failure):
    _, claims = issue_local(issuer)
    client = AsyncMock()
    client.eval.side_effect = failure("private redis secret")
    with pytest.raises(DynamicStoreUnavailable) as error:
        asyncio.run(issuer.issue(client, uuid.uuid4()) if operation == "issue"
                    else (consume if operation == "consume" else revoke)(client, claims))
    assert "private" not in str(error.value)
    assert client.eval.call_count == 1


@pytest.mark.parametrize("result", [None, True, "1", 2, -1])
def test_ambiguous_store_results_fail_closed(issuer, result):
    _, claims = issue_local(issuer)
    client = AsyncMock()
    client.eval.return_value = result
    with pytest.raises(DynamicStoreUnavailable):
        asyncio.run(consume(client, claims))


def test_unconfirmed_registration_and_wrong_signing_key(issuer, monkeypatch):
    client = AsyncMock()
    client.eval.return_value = 0
    with pytest.raises(DynamicStoreUnavailable):
        asyncio.run(issuer.issue(client, uuid.uuid4()))
    monkeypatch.setattr(issuer.keys, "signing_key", lambda _: ("bad", object()))
    with pytest.raises(KeyManagementError):
        asyncio.run(issuer.issue(client, uuid.uuid4()))


def test_real_redis_lifecycle_and_100_concurrent_consumers(issuer):
    url = os.getenv("TEST_QR_NONCE_REDIS_URL")
    if not url:
        pytest.skip("Set TEST_QR_NONCE_REDIS_URL to dedicated Redis")

    async def scenario():
        async with Redis.from_url(url, decode_responses=True) as client:
            tokens = [await issuer.issue(client, uuid.uuid4()) for _ in range(3)]
            claims = [issuer.validate(item.token) for item in tokens]
            keys = [state_key(item["jti"]) for item in claims]
            try:
                results = await asyncio.gather(*(consume(client, claims[0]) for _ in range(100)))
                assert results.count(True) == 1
                assert await client.hget(keys[0], "state") == "CONSUMED"
                assert not await revoke(client, claims[0])
                with pytest.raises(DynamicStoreUnavailable):
                    await register_state(client, claims[0])
                assert await revoke(client, claims[1])
                assert not await revoke(client, claims[1]) and not await consume(client, claims[1])
                assert await client.hget(keys[1], "state") == "REVOKED"
                record = await client.hgetall(keys[2])
                assert record == {"state": "ISSUED", "exp": str(claims[2]["exp"]), "typ": TOKEN_TYPE, "v": "1"}
                assert 0 < await client.ttl(keys[2]) <= 30
                assert claims[2]["jti"] not in keys[2]
                assert not await consume(client, {**claims[2], "exp": claims[2]["exp"] + 1})
                assert await consume(client, claims[2])
                assert not await consume(client, {**claims[2], "jti": "A" * 43})
                # Simulate an elapsed deadline with a surviving key to exercise explicit EXPIRED transition.
                expired = {**claims[2], "exp": int(time.time()) - 1}
                await client.hset(keys[2], mapping={"state": "ISSUED", "exp": expired["exp"]})
                assert not await consume(client, expired)
                assert await client.hget(keys[2], "state") == "EXPIRED"
                with pytest.raises(DynamicStoreUnavailable):
                    await register_state(client, expired)
                await client.delete(keys[2])
                assert not await consume(client, claims[2])
            finally:
                await client.delete(*keys)
    asyncio.run(scenario())


@pytest.fixture
def dynamic_flow(oidc_flow):
    server = oidc_flow[0]
    logged, _ = login(server)
    holder = logged.json()["user"]["id"]
    issued = server.client.post(ROOT + "/issue", headers=ORIGIN)
    assert issued.status_code == 200
    token = issued.json()["token"]
    claims = app.state.dynamic_qr_issuer.validate(token)
    with Session(server.engine) as session:
        session.get(SSOClient, "consumer").allowed_scopes = ["openid", SCOPE]
        session.commit()
    query = start(server, sub="dynamic-scanner", email="dynamic-scanner@school.edu")
    assert callback(server, query["state"][0]).status_code == 200
    access = exchange(server, scope=SCOPE)
    assert jwt.decode(access, options={"verify_signature": False})["sub"] != holder
    login(server)
    try:
        yield server, token, claims, access, holder
    finally:
        server.store.delete(state_key(claims["jti"]))


def verify(server, token, access):
    return server.client.post(ROOT + "/verify", json={"token": token},
                              headers={"Authorization": "Bearer " + access} if access else {})


def test_api_once_and_100_concurrent_requests(dynamic_flow, request):
    server, _, _, access, _ = dynamic_flow
    gate = Barrier(101, timeout=15)

    def scan():
        gate.wait()
        return verify(server, token, access)

    with ThreadPoolExecutor(max_workers=100) as pool:
        futures = [pool.submit(scan) for _ in range(100)]
        try:
            # Issue after starting the workers so fixture setup cannot spend the TTL.
            issued = server.client.post(ROOT + "/issue", headers=ORIGIN)
            assert issued.status_code == 200
            token = issued.json()["token"]
            claims = app.state.dynamic_qr_issuer.validate(token)
            request.addfinalizer(lambda: server.store.delete(state_key(claims["jti"])))
            started = time.monotonic()
            gate.wait()
            responses = [future.result(timeout=15) for future in futures]
        finally:
            gate.abort()
    assert time.monotonic() - started < 15
    assert server.store.time()[0] < claims["exp"], "Race must finish before token expiry"
    assert all(r.status_code == 200 for r in responses)
    assert [r.json() for r in responses].count({"valid": True}) == 1
    assert [r.json() for r in responses].count({"valid": False}) == 99
    assert server.store.hget(state_key(claims["jti"]), "state") == "CONSUMED"
    assert all(r.headers["cache-control"] == "no-store" for r in responses)
    assert verify(server, token, access).json() == {"valid": False}
    assert server.client.post(ROOT + "/revoke", headers=ORIGIN, json={"token": token}).json() == {"revoked": False}


def test_rotation_at_25_seconds_coexists_without_extending_old_token(dynamic_flow, monkeypatch):
    server, _, _, access, _ = dynamic_flow
    # Issue the earlier token 25 seconds in the past; both tokens are valid at the real Redis clock.
    from types import SimpleNamespace
    now = int(time.time())
    monkeypatch.setattr("qr.dynamic_tokens.time", SimpleNamespace(time=lambda: now - 25))
    old = server.client.post(ROOT + "/issue", headers=ORIGIN).json()["token"]
    claims = app.state.dynamic_qr_issuer.validate(old)
    monkeypatch.setattr("qr.dynamic_tokens.time", SimpleNamespace(time=lambda: now))
    response = server.client.post(ROOT + "/issue", headers=ORIGIN, json={})
    assert response.status_code == 200
    newer = response.json()
    decoded = jwt.decode(newer["token"], options={"verify_signature": False})
    try:
        assert newer["refresh_after"] == 25 and newer["token_type"] == TOKEN_TYPE
        assert decoded["exp"] == claims["exp"] + 25 and decoded["jti"] != claims["jti"]
        assert int(server.store.hget(state_key(claims["jti"]), "exp")) == claims["exp"]
        assert server.store.hget(state_key(decoded["jti"]), "state") == "ISSUED"
        assert verify(server, old, access).json() == {"valid": True}
        assert verify(server, newer["token"], access).json() == {"valid": True}
    finally:
        server.store.delete(state_key(decoded["jti"]), state_key(claims["jti"]))


def test_revoke_and_ownership(dynamic_flow):
    server, token, claims, access, holder = dynamic_flow
    query = start(server, sub="other-holder", email="other@school.edu")
    assert callback(server, query["state"][0]).status_code == 200
    assert server.client.post(ROOT + "/revoke", headers=ORIGIN, json={"token": token}).status_code == 403
    assert server.store.hget(state_key(claims["jti"]), "state") == "ISSUED"
    # Restore the holder through the existing provider/session flow.
    login(server)
    assert server.client.post(ROOT + "/revoke", headers=ORIGIN, json={"token": token}).json() == {"revoked": True}
    assert verify(server, token, access).json() == {"valid": False}


def test_scanner_authorization_precedes_consumption(dynamic_flow):
    server, token, claims, access, _ = dynamic_flow
    for bearer in (None, "bad", token):
        assert verify(server, token, bearer).status_code == 401
    assert verify(server, token, exchange(server, scope="openid")).status_code == 403
    assert server.store.hget(state_key(claims["jti"]), "state") == "ISSUED"
    assert verify(server, token, access).json() == {"valid": True}


@pytest.mark.parametrize("change,status", [("client-disabled", 401), ("scanner-disabled", 401), ("scope-removed", 403)])
def test_current_scanner_permissions(dynamic_flow, change, status):
    server, token, claims, access, holder = dynamic_flow
    from datetime import datetime, timezone
    with Session(server.engine) as session:
        if change == "client-disabled":
            session.get(SSOClient, "consumer").enabled = False
        elif change == "scope-removed":
            session.get(SSOClient, "consumer").allowed_scopes = ["openid"]
        else:
            scanner_id = jwt.decode(access, options={"verify_signature": False})["sub"]
            session.get(User, uuid.UUID(scanner_id)).disabled_at = datetime.now(timezone.utc)
        session.commit()
    assert verify(server, token, access).status_code == status
    assert server.store.hget(state_key(claims["jti"]), "state") == "ISSUED"


def test_browser_csrf_body_validation_and_no_token_echo(dynamic_flow):
    server, token, _, access, _ = dynamic_flow
    for endpoint, body in (("issue", {}), ("revoke", {"token": token})):
        assert server.client.post(ROOT + "/" + endpoint, json=body).status_code == 403
        assert server.client.post(ROOT + "/" + endpoint, headers={"Origin": "https://evil.example"}, json=body).status_code == 403
        assert server.client.post(ROOT + "/" + endpoint + "?jti=arbitrary", headers=ORIGIN, json=body).status_code == 400
    response = server.client.post(ROOT + "/verify", json={"token": token, "extra": token},
                                  headers={"Authorization": "Bearer " + access})
    assert response.status_code == 422 and token not in response.text
    assert response.headers["cache-control"] == "no-store"
    server.client.cookies.clear()
    assert server.client.post(ROOT + "/issue", headers=ORIGIN).status_code == 401
    assert server.client.post(ROOT + "/revoke", headers=ORIGIN, json={"token": token}).status_code == 401


@pytest.mark.parametrize("operation", ["issue", "verify", "revoke"])
@pytest.mark.parametrize("failure", [ConnectionError, TimeoutError])
def test_api_redis_failure(dynamic_flow, monkeypatch, operation, failure):
    server, token, _, access, _ = dynamic_flow

    async def broken(*a, **k):
        raise failure("private redis secret")
    monkeypatch.setattr(app.state.redis_client, "eval", broken)
    response = (verify(server, token, access) if operation == "verify" else
                server.client.post(ROOT + "/" + operation, headers=ORIGIN,
                                   json={"token": token} if operation == "revoke" else {}))
    assert response.status_code == 503 and "private" not in response.text
    assert response.headers["cache-control"] == "no-store"


@pytest.mark.parametrize("bad", ["signature", "payload", "audience", "issuer", "type", "expired", "future", "unknown", "static"])
def test_api_negative_tokens_return_only_false(dynamic_flow, bad):
    server, token, claims, access, _ = dynamic_flow
    issuer = app.state.dynamic_qr_issuer
    changed = dict(claims)
    if bad == "signature":
        token = sign(issuer, changed, key=SigningKey.generate("qr").private)
    elif bad == "payload":
        token = token.replace(".", ".A", 1)
    elif bad == "static":
        token = server.client.post("/api/v1/qr/credentials", headers=ORIGIN).json()["token"]
    else:
        if bad == "audience": changed["aud"] = "wrong"
        if bad == "issuer": changed["iss"] = "https://wrong.example"
        if bad == "type": changed["typ"] = "argus-qr+jwt"
        if bad == "expired": changed.update(iat=claims["iat"] - 31, nbf=claims["iat"] - 31, exp=claims["exp"] - 31)
        if bad == "future": changed.update(iat=claims["iat"] + 600, nbf=claims["iat"] + 600, exp=claims["exp"] + 600)
        if bad == "unknown": changed["jti"] = "A" * 43
        token = sign(issuer, changed)
    response = verify(server, token, access)
    assert response.status_code == 200 and response.json() == {"valid": False}
    assert server.store.hget(state_key(claims["jti"]), "state") == "ISSUED"


def test_openapi_documents_auth_contracts():
    document = app.openapi()
    for action in ("issue", "verify", "revoke"):
        operation = document["paths"][ROOT + "/" + action]["post"]
        assert operation["security"]
        assert all(str(code) in operation["responses"] for code in (200, 400, 401, 403, 422, 503))
    assert "qr:dynamic:verify" in document["paths"][ROOT + "/verify"]["post"]["description"]


def test_wrong_access_audience_and_invalid_revoke(dynamic_flow):
    server, token, claims, access, _ = dynamic_flow
    access_claims = jwt.decode(access, options={"verify_signature": False})
    access_claims["aud"] = "wrong-api"
    kid, key = app.state.token_issuer.keys.signing_key("sso")
    wrong_access = jwt.encode(access_claims, key, algorithm="EdDSA", headers={"kid": kid, "typ": "at+jwt"})
    assert verify(server, token, wrong_access).status_code == 401
    assert server.client.post(ROOT + "/revoke", headers=ORIGIN, json={"token": "bad"}).status_code == 400
    assert server.store.hget(state_key(claims["jti"]), "state") == "ISSUED"


@pytest.mark.parametrize("action", ["issue", "verify", "revoke"])
def test_missing_configuration_and_keys_fail_closed(dynamic_flow, monkeypatch, action):
    server, token, _, access, _ = dynamic_flow
    monkeypatch.setattr(app.state, "dynamic_qr_issuer", None)
    response = (verify(server, token, access) if action == "verify" else
                server.client.post(ROOT + "/" + action, headers=ORIGIN,
                                   json={"token": token} if action == "revoke" else {}))
    assert response.status_code == 503
