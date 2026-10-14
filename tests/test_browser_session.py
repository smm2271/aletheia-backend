import json
import time
from datetime import datetime, timezone

import pytest
from redis.exceptions import ConnectionError
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from auth import session as browser_session
from auth.session import COOKIE_NAME, SessionError, SessionSettings, session_key
from main import app
from models import User
from test_google_oauth import callback, flow, signing_key, start


def login(flow):
    query = start(flow)
    response = callback(flow, query["state"][0])
    assert response.status_code == 200
    return response, flow.client.cookies.get(COOKIE_NAME)


def set_token(flow, token):
    flow.client.cookies.clear()
    flow.client.cookies.set(COOKIE_NAME, token, domain="localhost.local", path="/")


def test_oauth_session_cookie_and_current_user(flow):
    response, token = login(flow)
    cookie = next(c for c in response.headers.get_list("set-cookie") if c.startswith(COOKIE_NAME + "="))
    assert "HttpOnly" in cookie and "SameSite=lax" in cookie and "Path=/" in cookie
    assert "Max-Age=28800" in cookie
    assert len(token) == 43
    assert token not in response.text
    assert response.json()["user"]["id"] not in cookie
    assert response.json()["user"]["email"] not in cookie
    key = session_key(token)
    assert token not in key
    record = json.loads(flow.store.get(key))
    assert set(record) == {"user_id", "created_at", "expires_at"}
    assert record["user_id"] == response.json()["user"]["id"]
    assert record["expires_at"] - record["created_at"] == 28800
    assert 0 < flow.store.ttl(key) <= 28800
    current = flow.client.get("/auth/me")
    assert current.status_code == 200
    assert current.json() == response.json()
    assert current.headers["cache-control"] == "no-store"
    assert "set-cookie" not in current.headers
    # The dependency uses the database's current profile, not cached roles.
    with Session(flow.engine) as session:
        user = session.scalar(select(User))
        user.email = "renamed@school.edu"
        session.commit()
    assert flow.client.get("/auth/me").json()["user"]["email"] == "renamed@school.edu"


def test_relogin_rotates_and_revokes_previous_session(flow):
    _, previous = login(flow)
    _, current = login(flow)
    assert current != previous
    assert flow.store.get(session_key(previous)) is None
    assert flow.client.get("/auth/me").status_code == 200
    set_token(flow, previous)
    assert flow.client.get("/auth/me").status_code == 401


def test_failed_oauth_preserves_existing_session(flow):
    _, token = login(flow)
    query = start(flow, email_verified=False)
    assert callback(flow, query["state"][0]).status_code == 401
    assert flow.client.cookies.get(COOKIE_NAME) == token
    assert flow.client.get("/auth/me").status_code == 200


def test_session_is_not_accepted_from_query_or_authorization_header(flow):
    _, token = login(flow)
    flow.client.cookies.clear()
    response = flow.client.get("/auth/me", params={"session_id": token}, headers={"Authorization": "Bearer " + token})
    assert response.status_code == 401


def test_logout_immediately_revokes_and_clears_cookie(flow):
    _, token = login(flow)
    response = flow.client.post("/auth/logout", headers={"Origin": "http://localhost"})
    assert response.status_code == 204
    assert "Max-Age=0" in response.headers["set-cookie"]
    assert COOKIE_NAME not in flow.client.cookies
    assert flow.store.get(session_key(token)) is None
    set_token(flow, token)
    assert flow.client.get("/auth/me").status_code == 401
    assert flow.client.post("/auth/logout", headers={"Origin": "http://localhost"}).status_code == 204


@pytest.mark.parametrize("origin", [None, "null", "https://evil.example", "http://localhost.evil.example"])
def test_logout_requires_exact_same_origin(flow, origin):
    _, token = login(flow)
    response = flow.client.post("/auth/logout", headers={} if origin is None else {"Origin": origin})
    assert response.status_code == 403
    assert flow.store.exists(session_key(token))
    assert flow.client.get("/auth/me").status_code == 200
    assert flow.client.get("/auth/logout").status_code == 405


@pytest.mark.parametrize("token", [None, "invalid", "a" * 43])
def test_absent_invalid_and_unknown_session_are_unauthenticated(flow, token):
    flow.client.cookies.clear()
    if token:
        set_token(flow, token)
    response = flow.client.get("/auth/me")
    assert response.status_code == 401
    assert response.json() == {"detail": "Unauthenticated"}
    assert "Max-Age=0" in response.headers["set-cookie"]


def test_expired_redis_key_is_rejected_even_with_cookie(flow):
    _, token = login(flow)
    flow.store.pexpire(session_key(token), 50)
    time.sleep(0.1)
    assert flow.client.get("/auth/me").status_code == 401


@pytest.mark.parametrize("record", ["not-json", "null", '{"user_id":"invalid"}', "expired"])
def test_corrupt_or_expired_metadata_is_rejected_and_revoked(flow, record):
    _, token = login(flow)
    key = session_key(token)
    if record == "expired":
        value = json.loads(flow.store.get(key))
        value["expires_at"] = int(time.time()) - 1
        record = json.dumps(value)
    flow.store.set(key, record, ex=60)
    assert flow.client.get("/auth/me").status_code == 401
    assert flow.store.get(key) is None


@pytest.mark.parametrize("action", ["disable", "delete"])
def test_disabled_or_deleted_user_invalidates_session(flow, action):
    _, token = login(flow)
    with Session(flow.engine) as session:
        user = session.scalar(select(User))
        if action == "disable":
            user.disabled_at = datetime.now(timezone.utc)
        else:
            session.execute(delete(User))
        session.commit()
    assert flow.client.get("/auth/me").status_code == 401
    assert flow.store.get(session_key(token)) is None


def test_redis_outage_fails_closed_without_logging_out(flow, monkeypatch):
    _, token = login(flow)
    async def unavailable(*args, **kwargs):
        raise ConnectionError("private Redis connection details")
    monkeypatch.setattr(app.state.redis_client, "get", unavailable)
    response = flow.client.get("/auth/me")
    assert response.status_code == 503
    assert response.json() == {"detail": "Session store unavailable"}
    assert "set-cookie" not in response.headers
    assert flow.client.cookies.get(COOKIE_NAME) == token


def test_failed_logout_does_not_claim_revocation(flow, monkeypatch):
    _, token = login(flow)
    async def unavailable(*args, **kwargs):
        raise ConnectionError("private Redis connection details")
    monkeypatch.setattr(app.state.redis_client, "delete", unavailable)
    response = flow.client.post("/auth/logout", headers={"Origin": "http://localhost"})
    assert response.status_code == 503
    assert "set-cookie" not in response.headers
    assert flow.store.exists(session_key(token))


def test_oauth_session_creation_failure_never_sets_cookie(flow, monkeypatch):
    async def unavailable(*args, **kwargs):
        raise ConnectionError("private Redis connection details")
    monkeypatch.setattr(app.state.redis_client, "eval", unavailable)
    query = start(flow)
    response = callback(flow, query["state"][0])
    assert response.status_code == 503
    assert COOKIE_NAME not in flow.client.cookies
    assert flow.client.get("/auth/me").status_code == 401


def test_secure_cookie_and_configurable_lifetime(flow, monkeypatch):
    monkeypatch.setenv("SESSION_PUBLIC_ORIGIN", "https://localhost")
    monkeypatch.setenv("SESSION_COOKIE_SECURE", "true")
    monkeypatch.setenv("SESSION_TTL_SECONDS", "120")
    response, token = login(flow)
    cookie = next(c for c in response.headers.get_list("set-cookie") if c.startswith(COOKIE_NAME + "="))
    assert "Secure" in cookie and "Max-Age=120" in cookie
    assert 0 < flow.store.ttl(session_key(token)) <= 120


@pytest.mark.parametrize("setting,value", [
    ("SESSION_TTL_SECONDS", "0"), ("SESSION_TTL_SECONDS", "invalid"),
    ("SESSION_COOKIE_SECURE", "maybe"), ("SESSION_PUBLIC_ORIGIN", "http://remote.example"),
    ("SESSION_PUBLIC_ORIGIN", "http://localhost/path"),
])
def test_invalid_session_configuration_is_rejected(monkeypatch, setting, value):
    monkeypatch.setenv("SESSION_PUBLIC_ORIGIN", "http://localhost")
    monkeypatch.setenv("SESSION_COOKIE_SECURE", "false")
    monkeypatch.setenv(setting, value)
    with pytest.raises(SessionError) as error:
        SessionSettings.from_environment()
    assert error.value.status == 503
