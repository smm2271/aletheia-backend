"""Real DB / Redis chain: holder Session -> static QR -> scanner code exchange.

Google identity responses are controlled; authorization, JWT signatures, mapping
lookups and Redis nonce claims use the application implementations.
"""
import hashlib
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from redis.exceptions import ConnectionError as RedisConnectionError
from sqlalchemy.orm import Session

from main import app
from models import QRCredential, SSOClient, User
from qr.nonces import NONCE_NAMESPACE, generate_nonce
from test_authorization import TEST_CHALLENGE, TEST_VERIFIER, auth_flow, authorize, issued_code, register
from test_browser_session import login
from test_google_oauth import callback, flow, signing_key, start
from test_oidc_integration import oidc_flow

VERIFY = "/api/v1/qr/static/verify"
SCOPE = "qr:static:verify"
ORIGIN = {"Origin": "http://localhost"}


def exchange(server, client_id="consumer", scope=SCOPE):
    with Session(server.engine) as session:
        client = session.get(SSOClient, client_id)
        uri = client.redirect_uris[0]
    code = issued_code(authorize(server, {
        "response_type": "code", "client_id": client_id, "redirect_uri": uri,
        "scope": scope, "code_challenge": TEST_CHALLENGE, "code_challenge_method": "S256",
    }))
    response = server.client.post("/token", data={
        "grant_type": "authorization_code", "client_id": client_id, "client_secret": "secret",
        "code": code, "redirect_uri": uri, "code_verifier": TEST_VERIFIER,
    })
    assert response.status_code == 200
    return response.json()["access_token"]


def verify(server, qr, nonce=None, access=None):
    nonce = nonce or generate_nonce()
    if access:
        # Test cleanup only; this untrusted decode never participates in authorization.
        client_id = jwt.decode(access, options={"verify_signature": False})["client_id"]
        server.qr_nonce_keys.add(f"{NONCE_NAMESPACE}:{hashlib.sha256(client_id.encode()).hexdigest()}:"
                                 f"{hashlib.sha256(nonce.encode('ascii')).hexdigest()}")
    return server.client.post(VERIFY, json={"token": qr, "nonce": nonce},
                              headers={"Authorization": "Bearer " + access} if access else {})


@pytest.fixture
def verification_flow(oidc_flow):
    server = oidc_flow[0]
    holder, _ = login(server)
    holder_id = uuid.UUID(holder.json()["user"]["id"])
    issued = server.client.post("/api/v1/qr/credentials", headers=ORIGIN, json={})
    assert issued.status_code == 200
    qr = issued.json()["token"]
    query = start(server, sub="scanner-subject", email="scanner@school.edu")
    scanner = callback(server, query["state"][0])
    assert scanner.status_code == 200
    scanner_id = uuid.UUID(scanner.json()["user"]["id"])
    assert scanner_id != holder_id
    with Session(server.engine) as session:
        session.get(SSOClient, "consumer").allowed_scopes = ["openid", SCOPE]
        session.commit()
    server.qr_nonce_keys = set()
    try:
        yield server, holder_id, scanner_id, qr, exchange(server)
    finally:
        if server.qr_nonce_keys:
            server.store.delete(*server.qr_nonce_keys)


def test_holder_to_scanner_exchange_replay_and_minimal_disclosure(verification_flow):
    server, holder, scanner, qr, access = verification_flow
    nonce = generate_nonce()
    accepted = verify(server, qr, nonce, access)
    assert accepted.status_code == 200 and accepted.json() == {"valid": True}
    assert accepted.headers["cache-control"] == "no-store"
    assert "set-cookie" not in accepted.headers
    assert all(secret not in accepted.text for secret in (str(holder), str(scanner), qr, access, nonce))
    assert verify(server, qr, nonce, access).status_code == 409
    # A static credential is reusable. A new verifier-generated nonce is required.
    assert verify(server, qr, access=access).json() == {"valid": True}


def test_unauthorized_and_invalid_requests_do_not_spend_nonce(verification_flow):
    server, _, _, qr, access = verification_flow
    nonce = generate_nonce()
    # A scanner Browser Session is present, but cannot authorize this resource API.
    assert verify(server, qr, nonce).status_code == 401
    without_scope = exchange(server, scope="openid")
    assert verify(server, qr, nonce, without_scope).status_code == 403
    assert verify(server, qr + "tampered", nonce, access).status_code == 400
    assert verify(server, qr, nonce, access).status_code == 200


def test_nonce_scope_is_client_not_credential(verification_flow):
    server, _, _, qr, access = verification_flow
    register(server, client_id="scanner-two", allowed_scopes=[SCOPE])
    second_access = exchange(server, "scanner-two")
    nonce = generate_nonce()
    assert verify(server, qr, nonce, access).status_code == 200
    assert verify(server, qr, nonce, second_access).status_code == 200
    # The scanner also owns a different credential: same Client nonce must conflict.
    other = server.client.post("/api/v1/qr/credentials", headers=ORIGIN).json()["token"]
    assert other != qr
    assert verify(server, other, nonce, access).status_code == 409
    assert verify(server, other, access=access).status_code == 200


def test_high_concurrency_atomically_accepts_once(verification_flow):
    server, _, _, qr, access = verification_flow
    nonce = generate_nonce()
    with ThreadPoolExecutor(max_workers=12) as pool:
        responses = list(pool.map(lambda _: verify(server, qr, nonce, access), range(24)))
    statuses = [response.status_code for response in responses]
    assert statuses.count(200) == 1
    assert statuses.count(409) == 23


def test_expired_nonce_rejected_but_fresh_nonce_can_reuse_static_qr(verification_flow):
    server, _, _, qr, access = verification_flow
    expired = generate_nonce(now=int(time.time()) - 301)
    assert verify(server, qr, expired, access).status_code == 400
    assert verify(server, qr, access=access).json() == {"valid": True}


@pytest.mark.parametrize("change", ["holder-disabled", "scanner-disabled", "client-disabled", "scope-removed", "mapping-expired"])
def test_current_state_changes_deny_then_allow_same_unused_nonce(verification_flow, change):
    server, holder, scanner, qr, access = verification_flow
    nonce = generate_nonce()
    with Session(server.engine) as session:
        if change.endswith("disabled") and change != "client-disabled":
            row = session.get(User, holder if change == "holder-disabled" else scanner)
            row.disabled_at = datetime.now(timezone.utc)
        elif change == "client-disabled":
            session.get(SSOClient, "consumer").enabled = False
        elif change == "scope-removed":
            session.get(SSOClient, "consumer").allowed_scopes = ["openid"]
        else:
            row = session.get(QRCredential, holder)
            original = row.issued_at, row.expires_at
            row.issued_at = datetime.now(timezone.utc) - timedelta(hours=2)
            row.expires_at = datetime.now(timezone.utc) - timedelta(hours=1)
        session.commit()
    rejected = verify(server, qr, nonce, access)
    assert rejected.status_code in {400, 401, 403}
    assert rejected.headers["cache-control"] == "no-store"
    with Session(server.engine) as session:
        if change.endswith("disabled") and change != "client-disabled":
            session.get(User, holder if change == "holder-disabled" else scanner).disabled_at = None
        elif change == "client-disabled":
            session.get(SSOClient, "consumer").enabled = True
        elif change == "scope-removed":
            session.get(SSOClient, "consumer").allowed_scopes = ["openid", SCOPE]
        else:
            row = session.get(QRCredential, holder)
            row.issued_at, row.expires_at = original
        session.commit()
    assert verify(server, qr, nonce, access).status_code == 200


def test_redis_claim_failure_fails_closed_then_retry_can_succeed(verification_flow, monkeypatch):
    server, _, _, qr, access = verification_flow
    nonce = generate_nonce()
    original = app.state.redis_client.set

    async def unavailable(*args, **kwargs):
        raise RedisConnectionError("private redis connection details")

    monkeypatch.setattr(app.state.redis_client, "set", unavailable)
    response = verify(server, qr, nonce, access)
    assert response.status_code == 503
    assert "private" not in response.text
    assert response.headers["cache-control"] == "no-store"
    monkeypatch.setattr(app.state.redis_client, "set", original)
    assert verify(server, qr, nonce, access).status_code == 200
