import base64
import hashlib
import json
import os
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from alembic import command
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from google.auth import crypt, jwt
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session
from redis import Redis

from auth import google
from auth import affiliation
from auth import session as browser_session
from routes import auth as auth_routes
from auth.affiliation import determine_affiliation
from main import app
from models import Affiliation, ExternalIdentity, OAuthAttempt, User


@pytest.fixture(scope="module")
def signing_key():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    public = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    return crypt.RSASigner.from_string(private, key_id="test-key"), public


@pytest.fixture
def flow(database, monkeypatch, signing_key):
    engine, config = database
    command.upgrade(config, "head")
    for key, value in {
        "GOOGLE_CLIENT_ID": "test-client", "GOOGLE_CLIENT_SECRET": "test-secret",
        "GOOGLE_REDIRECT_URI": "http://testserver/auth/google/callback", "GOOGLE_HOSTED_DOMAIN": "",
        "SESSION_PUBLIC_ORIGIN": "http://localhost", "SESSION_COOKIE_SECURE": "false",
    }.items():
        monkeypatch.setenv(key, value)
    # HTTP is permitted only on loopback, so give TestClient the configured host.
    monkeypatch.setenv("GOOGLE_REDIRECT_URI", "http://localhost/auth/google/callback")
    provider = SimpleNamespace(claims={}, posts=[], status=200, malformed=False, corrupt=False, timeout=False)

    class ProviderClient:
        def __init__(self, **kwargs):
            assert kwargs["timeout"] == 10
            assert kwargs["follow_redirects"] is False

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def post(self, url, data):
            assert url == google.TOKEN_URL
            provider.posts.append(data)
            if provider.timeout:
                raise httpx.ReadTimeout("provider timeout with sensitive context")
            token = jwt.encode(signing_key[0], provider.claims).decode()
            if provider.corrupt:
                pieces = token.split(".")
                pieces[-1] = "A" * len(pieces[-1])
                token = ".".join(pieces)
            return httpx.Response(provider.status, json={} if provider.malformed else {"id_token": token, "access_token": "private-access-token"})

    monkeypatch.setattr(google.httpx, "Client", ProviderClient)
    monkeypatch.setattr(google.BoundedGoogleRequest, "__call__", lambda *a, **k: SimpleNamespace(
        status=200, data=json.dumps({"test-key": signing_key[1]}).encode(),
    ))
    created_keys = []
    original_create_session = browser_session.create_session
    async def record_session(*args, **kwargs):
        token = await original_create_session(*args, **kwargs)
        created_keys.append(browser_session.session_key(token))
        return token
    monkeypatch.setattr(auth_routes, "create_session", record_session)
    with Redis.from_url(os.environ["TEST_REDIS_URL"], decode_responses=True) as store:
        try:
            with TestClient(app, base_url="http://localhost") as client:
                yield SimpleNamespace(client=client, engine=engine, config=config, provider=provider, store=store)
        finally:
            if created_keys:
                store.delete(*created_keys)


def start(flow, **claims):
    response = flow.client.get("/auth/google/login", follow_redirects=False)
    assert response.status_code == 302
    query = parse_qs(urlsplit(response.headers["location"]).query)
    now = int(time.time())
    flow.provider.claims = {
        "iss": "https://accounts.google.com", "aud": "test-client", "iat": now, "exp": now + 300,
        "sub": "stable-subject", "nonce": query["nonce"][0], "email": "s1234567@school.edu",
        "email_verified": True, "name": "Student", "picture": "https://example.com/avatar.png",
        **claims,
    }
    return query


def callback(flow, state, **params):
    return flow.client.get("/auth/google/callback", params={"state": state, "code": "test-code", **params})


def assert_empty(flow):
    with Session(flow.engine) as session:
        assert session.scalar(select(func.count()).select_from(User)) == 0
        assert session.scalar(select(func.count()).select_from(ExternalIdentity)) == 0


def test_login_pkce_and_repeat_login_preserve_identity(flow, caplog):
    query = start(flow)
    response = callback(flow, query["state"][0])
    assert response.status_code == 200
    user_id = response.json()["user"]["id"]
    assert response.json()["user"]["affiliation"] == "student"
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert google.COOKIE_NAME not in flow.client.cookies
    body = flow.provider.posts[0]
    challenge = base64.urlsafe_b64encode(hashlib.sha256(body["code_verifier"].encode()).digest()).rstrip(b"=").decode()
    assert query["code_challenge"] == [challenge]
    assert query["code_challenge_method"] == ["S256"]
    assert query["scope"] == ["openid email profile"]
    assert body["client_secret"] == "test-secret"
    assert body["redirect_uri"] == "http://localhost/auth/google/callback"
    assert "test-secret" not in caplog.text
    assert "private-access-token" not in response.text + caplog.text
    with Session(flow.engine) as session:
        user = session.scalar(select(User))
        user.affiliation = Affiliation.TEACHER
        session.commit()
    # Changed email must still resolve the original subject, without replacing
    # an existing locally managed affiliation with the provisioning policy.
    query = start(flow, email="teacher@school.edu")
    response = callback(flow, query["state"][0])
    assert response.status_code == 200
    assert response.json()["user"]["id"] == user_id
    assert response.json()["user"]["affiliation"] == "teacher"
    with Session(flow.engine) as session:
        assert session.scalar(select(func.count()).select_from(ExternalIdentity)) == 1
        assert session.scalar(select(func.count()).select_from(User)) == 1


@pytest.mark.parametrize("override", [
    {"iss": "https://evil.example"}, {"aud": "other-client"}, {"exp": 1},
    {"iat": 9999999999}, {"nonce": "wrong-nonce"}, {"nonce": "非ASCII"}, {"email_verified": False},
    {"email_verified": "true"}, {"sub": ""}, {"email": ""}, {"azp": "other-client"},
])
def test_invalid_signed_identity_never_creates_user(flow, override):
    query = start(flow, **override)
    response = callback(flow, query["state"][0])
    assert response.status_code == 401
    assert_empty(flow)
    assert callback(flow, query["state"][0]).status_code == 400


@pytest.mark.parametrize("condition,expected", [("corrupt", 401), ("malformed", 401), ("timeout", 502), ("status", 401)])
def test_provider_failures_are_generic_and_atomic(flow, condition, expected, caplog):
    query = start(flow)
    setattr(flow.provider, condition, 400 if condition == "status" else True)
    response = callback(flow, query["state"][0])
    assert response.status_code == expected
    assert "sensitive context" not in response.text + caplog.text
    assert "test-secret" not in response.text + caplog.text
    assert_empty(flow)


def test_state_browser_binding_expiry_denial_and_replay(flow):
    query = start(flow)
    browser = flow.client.cookies.get(google.COOKIE_NAME)
    flow.client.cookies.clear()
    assert callback(flow, query["state"][0]).status_code == 400
    flow.client.cookies.set(google.COOKIE_NAME, browser, domain="localhost.local", path=google.COOKIE_PATH)
    response = callback(flow, query["state"][0], error="access_denied")
    assert response.status_code == 400
    assert response.json()["detail"] == "Google authorization denied"
    assert not flow.provider.posts
    flow.client.cookies.set(google.COOKIE_NAME, browser, domain="localhost.local", path=google.COOKIE_PATH)
    assert callback(flow, query["state"][0]).status_code == 400
    query = start(flow)
    with Session(flow.engine) as session:
        session.execute(update(OAuthAttempt).values(expires_at=datetime.now(timezone.utc) - timedelta(seconds=1)))
        session.commit()
    assert callback(flow, query["state"][0]).status_code == 400
    assert_empty(flow)


def test_domain_uses_signed_hd_not_email_suffix(flow, monkeypatch):
    monkeypatch.setenv("GOOGLE_HOSTED_DOMAIN", "school.edu")
    query = start(flow)
    assert query["hd"] == ["school.edu"]
    assert callback(flow, query["state"][0]).status_code == 403
    assert_empty(flow)
    query = start(flow, hd="school.edu")
    assert callback(flow, query["state"][0]).status_code == 200


def test_email_collision_does_not_link_accounts(flow):
    with Session(flow.engine) as session:
        session.add(User(email="s1234567@school.edu", affiliation=Affiliation.ALUMNI))
        session.commit()
    query = start(flow)
    assert callback(flow, query["state"][0]).status_code == 409
    with Session(flow.engine) as session:
        assert session.scalar(select(func.count()).select_from(User)) == 1
        assert session.scalar(select(func.count()).select_from(ExternalIdentity)) == 0


def test_disabled_user_cannot_log_in(flow):
    query = start(flow)
    assert callback(flow, query["state"][0]).status_code == 200
    with Session(flow.engine) as session:
        user = session.scalar(select(User))
        user.disabled_at = datetime.now(timezone.utc)
        session.commit()
    query = start(flow)
    assert callback(flow, query["state"][0]).status_code == 403


def test_unmatched_first_login_is_teacher(flow):
    query = start(flow, email="teacher@school.edu")
    response = callback(flow, query["state"][0])
    assert response.status_code == 200
    assert response.json()["user"]["affiliation"] == "teacher"


def test_concurrent_provisioning_has_one_user_and_identity(flow):
    start(flow)
    settings = google.GoogleSettings.from_environment()
    def provision(_):
        with Session(flow.engine) as session:
            return google.resolve_user(session, flow.provider.claims, settings).id
    with ThreadPoolExecutor(max_workers=2) as executor:
        ids = list(executor.map(provision, range(2)))
    assert ids[0] == ids[1]
    with Session(flow.engine) as session:
        assert session.scalar(select(func.count()).select_from(User)) == 1
        assert session.scalar(select(func.count()).select_from(ExternalIdentity)) == 1


def test_concurrent_callbacks_consume_state_only_once(flow):
    query = start(flow)
    state = query["state"][0]
    browser = flow.client.cookies.get(google.COOKIE_NAME)
    def consume(_):
        with Session(flow.engine) as session:
            try:
                google.consume_attempt(session, state, browser)
                return True
            except google.OAuthError:
                return False
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(consume, range(2)))
    assert sorted(results) == [False, True]


@pytest.mark.parametrize("params", [{}, {"state": "unknown", "code": "test"}, {"error": "access_denied"}])
def test_missing_or_unknown_state_never_exchanges_code(flow, params):
    start(flow)
    response = flow.client.get("/auth/google/callback", params=params)
    assert response.status_code == 400
    assert not flow.provider.posts
    assert_empty(flow)


def test_duplicate_parameters_and_missing_code_are_rejected(flow):
    query = start(flow)
    response = flow.client.get("/auth/google/callback", params=[
        ("state", query["state"][0]), ("code", "one"), ("code", "two"),
    ])
    assert response.status_code == 400
    query = start(flow)
    response = flow.client.get("/auth/google/callback", params={"state": query["state"][0]})
    assert response.status_code == 400
    assert not flow.provider.posts
    assert_empty(flow)


def test_modified_policy_can_refuse_provisioning(flow, monkeypatch):
    monkeypatch.setattr(affiliation, "determine_affiliation", lambda claims: None)
    query = start(flow)
    assert callback(flow, query["state"][0]).status_code == 403
    assert_empty(flow)


def test_missing_required_token_timestamp_is_rejected(flow):
    query = start(flow)
    del flow.provider.claims["exp"]
    assert callback(flow, query["state"][0]).status_code == 401
    assert_empty(flow)


@pytest.mark.parametrize("email,expected", [
    ("s1234567@school.edu", Affiliation.STUDENT), ("j7654321@school.edu", Affiliation.STUDENT),
    ("s123456@school.edu", Affiliation.TEACHER), ("s12345678@school.edu", Affiliation.TEACHER),
    ("x1234567@school.edu", Affiliation.TEACHER), ("s１２３４５６７@school.edu", Affiliation.TEACHER),
    ("xs1234567@school.edu", Affiliation.TEACHER), ("s1234567extra@school.edu", Affiliation.TEACHER),
])
def test_editable_affiliation_rule(email, expected):
    assert determine_affiliation({"email": email}) == expected


def test_unconfigured_login_and_insecure_remote_redirect(flow, monkeypatch):
    monkeypatch.delenv("GOOGLE_CLIENT_SECRET")
    assert flow.client.get("/auth/google/login").status_code == 503
    monkeypatch.setenv("GOOGLE_CLIENT_SECRET", "test-secret")
    monkeypatch.setenv("GOOGLE_REDIRECT_URI", "http://example.com/auth/google/callback")
    assert flow.client.get("/auth/google/login").status_code == 503
    monkeypatch.setenv("GOOGLE_REDIRECT_URI", "https://example.com/auth/google/callback")
    response = flow.client.get("/auth/google/login", follow_redirects=False)
    cookie = response.headers["set-cookie"]
    assert "Secure" in cookie and "HttpOnly" in cookie and "SameSite=lax" in cookie
