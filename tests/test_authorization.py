import base64
import hashlib
import json
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi import HTTPException
from sqlalchemy.orm import Session

from main import app
from models import ClientType, SSOClient, TrustLevel
from routes import authorization as routes
from sso import authorization as service
from sso.authorization import CODE_PREFIX, CONTEXT_COOKIE, CONTEXT_PREFIX, consume_code, context_fingerprint
from sso.clients import hash_secret
from test_browser_session import login
from test_google_oauth import callback, flow, signing_key, start


@pytest.fixture
def auth_flow(flow, monkeypatch):
    keys = []
    original_code, original_context = routes.issue_code, routes.store_context
    async def record_code(*args):
        code = await original_code(*args)
        keys.append(CODE_PREFIX + context_fingerprint(code))
        return code
    async def record_context(*args):
        context = await original_context(*args)
        keys.append(CONTEXT_PREFIX + context_fingerprint(context))
        return context
    monkeypatch.setattr(routes, "issue_code", record_code)
    monkeypatch.setattr(routes, "store_context", record_context)
    try:
        yield flow
    finally:
        if keys:
            flow.store.delete(*keys)


TEST_VERIFIER = "v" * 64
TEST_CHALLENGE = base64.urlsafe_b64encode(hashlib.sha256(TEST_VERIFIER.encode("ascii")).digest()).rstrip(b"=").decode()


def register(flow, **changes):
    data = {
        "client_id": "consumer", "name": "Consumer", "client_type": ClientType.CONFIDENTIAL,
        "trust_level": TrustLevel.FIRST_PARTY, "enabled": True,
        "redirect_uris": ["https://consumer.example/callback?fixed=1"],
        "allowed_scopes": ["openid", "profile"], "secret_hash": hash_secret("secret"),
        **changes,
    }
    with Session(flow.engine) as session:
        session.add(SSOClient(**data))
        session.commit()
    return {"response_type": "code", "client_id": data["client_id"], "redirect_uri": data["redirect_uris"][0],
            "scope": "openid profile", "state": "unchanged +&/雪",
            "code_challenge": TEST_CHALLENGE, "code_challenge_method": "S256"}


def authorize(flow, params):
    return flow.client.get("/authorize", params=params, follow_redirects=False)


def issued_code(response):
    assert response.status_code == 302
    return parse_qs(urlsplit(response.headers["location"]).query)["code"][0]


def test_first_party_uses_session_and_code_bindings(auth_flow):
    response, _ = login(auth_flow)
    params = register(auth_flow)
    authorized = authorize(auth_flow, params)
    code = issued_code(authorized)
    parsed = parse_qs(urlsplit(authorized.headers["location"]).query)
    assert parsed["state"] == [params["state"]] and parsed["fixed"] == ["1"]
    assert len(code) == 43 and response.json()["user"]["id"] not in code
    assert authorized.headers["cache-control"] == "no-store"
    assert authorized.headers["referrer-policy"] == "no-referrer"
    record = json.loads(auth_flow.store.get(CODE_PREFIX + context_fingerprint(code)))
    assert record["user_id"] == response.json()["user"]["id"]
    assert record["client_id"] == "consumer"
    assert record["redirect_uri"] == params["redirect_uri"]
    assert record["scope"] == ["openid", "profile"]
    assert 0 < auth_flow.store.ttl(CODE_PREFIX + context_fingerprint(code)) <= 120
    assert len(auth_flow.provider.posts) == 1  # Only the original login.


@pytest.mark.parametrize("update", [
    {"client_id": "unknown"}, {"redirect_uri": "https://evil.example/callback"},
    {"redirect_uri": "https://consumer.example/callback?fixed=1&extra=yes"},
    {"scope": "openid email"}, {"response_type": "token"},
])
def test_invalid_request_rejected_before_login(auth_flow, update):
    params = register(auth_flow)
    assert authorize(auth_flow, {**params, **update}).status_code == 400
    assert not auth_flow.provider.posts
    assert CONTEXT_COOKIE not in auth_flow.client.cookies


def test_disabled_client_cannot_authorize(auth_flow):
    params = register(auth_flow, enabled=False)
    assert authorize(auth_flow, params).status_code == 400


def test_external_consent_boundary_never_issues_code(auth_flow):
    login(auth_flow)
    params = register(auth_flow, trust_level=TrustLevel.EXTERNAL)
    response = authorize(auth_flow, params)
    assert response.status_code == 403 and response.json()["policy"] == "consent_required"
    assert "location" not in response.headers


def test_anonymous_google_login_resumes_original_request(auth_flow):
    params = register(auth_flow)
    response = authorize(auth_flow, params)
    assert response.headers["location"] == "/auth/google/login?continue=authorization"
    # Fill the real signed test Google token, then replace the standalone attempt
    # with the continuation-bound attempt requested by the authorization flow.
    start(auth_flow)
    google_response = auth_flow.client.get(response.headers["location"], follow_redirects=False)
    google_query = parse_qs(urlsplit(google_response.headers["location"]).query)
    auth_flow.provider.claims["nonce"] = google_query["nonce"][0]
    callback_response = auth_flow.client.get("/auth/google/callback", params={"state": google_query["state"][0], "code": "test-code"}, follow_redirects=False)
    assert callback_response.status_code == 303
    assert callback_response.headers["location"] == "/authorize/resume"
    resumed = auth_flow.client.get("/authorize/resume", follow_redirects=False)
    code = issued_code(resumed)
    assert parse_qs(urlsplit(resumed.headers["location"]).query)["state"] == [params["state"]]
    assert CONTEXT_COOKIE not in auth_flow.client.cookies
    assert auth_flow.store.exists(CODE_PREFIX + context_fingerprint(code))
    assert auth_flow.client.get("/authorize/resume", follow_redirects=False).status_code == 400


def test_standalone_google_login_does_not_resume_unbound_context(auth_flow):
    params = register(auth_flow)
    authorize(auth_flow, params)
    query = start(auth_flow)
    assert callback(auth_flow, query["state"][0]).status_code == 200


def test_resume_revalidates_disabled_client(auth_flow):
    params = register(auth_flow)
    authorize(auth_flow, params)
    login(auth_flow)
    with Session(auth_flow.engine) as session:
        session.get(SSOClient, "consumer").enabled = False
        session.commit()
    assert auth_flow.client.get("/authorize/resume", follow_redirects=False).status_code == 400


def test_code_single_use_binding_and_expiry(auth_flow):
    login(auth_flow)
    params = register(auth_flow)
    code = issued_code(authorize(auth_flow, params))
    def consume(client_id="consumer", uri=params["redirect_uri"], verifier=TEST_VERIFIER):
        return auth_flow.client.portal.call(consume_code, app.state.redis_client, code, client_id, uri, verifier)
    with pytest.raises(HTTPException):
        consume("other-client")
    with pytest.raises(HTTPException):
        consume(uri="https://evil.example")
    assert consume()["client_id"] == "consumer"
    with pytest.raises(HTTPException):
        consume()
    expired = issued_code(authorize(auth_flow, params))
    auth_flow.store.pexpire(CODE_PREFIX + context_fingerprint(expired), 50)
    time.sleep(0.1)
    with pytest.raises(HTTPException):
        auth_flow.client.portal.call(consume_code, app.state.redis_client, expired, "consumer", params["redirect_uri"], TEST_VERIFIER)


def test_public_pkce_and_atomic_concurrent_consumption(auth_flow):
    login(auth_flow)
    params = register(auth_flow, client_type=ClientType.PUBLIC, secret_hash=None)
    verifier = "v" * 64
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    params.update(code_challenge=challenge, code_challenge_method="S256")
    code = issued_code(authorize(auth_flow, params))
    with pytest.raises(HTTPException):
        auth_flow.client.portal.call(consume_code, app.state.redis_client, code, "consumer", params["redirect_uri"], "x" * 64)
    def consume(_):
        try:
            auth_flow.client.portal.call(consume_code, app.state.redis_client, code, "consumer", params["redirect_uri"], verifier)
            return True
        except HTTPException:
            return False
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(consume, range(2))) == [False, True]


def test_pkce_required_for_all_clients(auth_flow):
    login(auth_flow)
    confidential = register(auth_flow)
    without_pkce = {k: v for k, v in confidential.items() if not k.startswith("code_challenge")}
    assert authorize(auth_flow, without_pkce).status_code == 400
    with_plain = {**confidential, "code_challenge_method": "plain"}
    assert authorize(auth_flow, with_plain).status_code == 400


def test_duplicate_parameters_are_rejected(auth_flow):
    params = register(auth_flow)
    response = auth_flow.client.get("/authorize", params=list(params.items()) + [("client_id", "other")], follow_redirects=False)
    assert response.status_code == 400


def test_registered_uri_encoding_and_empty_state_are_preserved(auth_flow):
    login(auth_flow)
    uri = "https://consumer.example/callback?fixed=%2f"
    params = register(auth_flow, redirect_uris=[uri])
    params["state"] = ""
    response = authorize(auth_flow, params)
    assert response.headers["location"].startswith(uri + "&code=")
    assert parse_qs(urlsplit(response.headers["location"]).query, keep_blank_values=True)["state"] == [""]


def test_expired_continuation_is_rejected(auth_flow):
    params = register(auth_flow)
    authorize(auth_flow, params)
    token = auth_flow.client.cookies.get(CONTEXT_COOKIE)
    auth_flow.store.pexpire(CONTEXT_PREFIX + context_fingerprint(token), 50)
    time.sleep(0.1)
    login(auth_flow)
    assert auth_flow.client.get("/authorize/resume", follow_redirects=False).status_code == 400


@pytest.mark.parametrize("uri", ["https://consumer.example/callback#", "https://consumer.example/callback?state=", "https://consumer.example/call\nback"])
def test_malformed_registered_uri_cannot_receive_code(auth_flow, uri):
    login(auth_flow)
    params = register(auth_flow, redirect_uris=[uri])
    assert authorize(auth_flow, params).status_code == 400
