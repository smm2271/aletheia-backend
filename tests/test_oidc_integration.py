import json
import os
import time
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx
import jwt
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from redis.exceptions import ConnectionError as RedisConnectionError

from demo_client.app import ClientSettings, FLOW_COOKIE, FLOW_PREFIX, SESSION_COOKIE, SESSION_PREFIX, create_app, fingerprint
from main import app
from models import SSOClient, TrustLevel
from signing_keys import FileKeyProvider, KeyRing, SigningKey, save_key_file
from test_authorization import auth_flow, register
from test_browser_session import login
from test_google_oauth import flow, signing_key


@pytest.fixture
def oidc_flow(request, monkeypatch, tmp_path):
    ring = KeyRing([SigningKey.generate("sso"), SigningKey.generate("qr")])
    path = tmp_path / "keys.json"
    save_key_file(path, ring, create=True)
    monkeypatch.setattr(app.state, "sso_key_provider", None)
    monkeypatch.setenv("SIGNING_KEYS_FILE", str(path))
    monkeypatch.setenv("SSO_ISSUER", "http://localhost")
    monkeypatch.setenv("SSO_ACCESS_AUDIENCE", "argus-api")
    monkeypatch.setenv("SSO_ID_TOKEN_TTL_SECONDS", "300")
    monkeypatch.setenv("SSO_ACCESS_TOKEN_TTL_SECONDS", "300")
    server = request.getfixturevalue("auth_flow")
    register(server, redirect_uris=["http://127.0.0.1:8001/callback"])
    # Give the separate client a real Redis connection, in its own namespace.
    config = ClientSettings("http://localhost", "consumer", "secret", redis_url=os.environ["TEST_REDIS_URL"])
    demo = create_app(config)
    calls = []

    class RoutingHTTP:
        corrupt = None

        async def get(self, url):
            calls.append(("GET", url))
            response = server.client.get(url)
            if self.corrupt == "discovery" and url.endswith("openid-configuration"):
                document = response.json()
                document["token_endpoint"] = "https://attacker.example/token"
                return httpx.Response(200, json=document, request=httpx.Request("GET", url))
            return response

        async def post(self, url, **kwargs):
            calls.append(("POST", url))
            if self.corrupt == "pkce":
                kwargs["data"]["code_verifier"] = "w" * 43
            response = server.client.post(url, **kwargs)
            if self.corrupt in {"nonce", "signature", "audience", "expired", "issuer", "kid", "type"} and response.status_code == 200:
                body = response.json()
                claims = jwt.decode(body["id_token"], options={"verify_signature": False})
                kid, key = app.state.token_issuer.keys.signing_key("sso")
                if self.corrupt == "nonce":
                    claims["nonce"] = "wrong"
                elif self.corrupt == "audience":
                    claims["aud"] = "another-client"
                elif self.corrupt == "issuer":
                    claims["iss"] = "https://another-issuer.example"
                elif self.corrupt == "expired":
                    claims["exp"] = int(time.time()) - 1
                elif self.corrupt == "signature":
                    key = SigningKey.generate("sso").private
                elif self.corrupt == "kid":
                    kid = "unknown"
                if self.corrupt == "type":
                    body["id_token"] = body["access_token"]
                else:
                    body["id_token"] = jwt.encode(claims, key, algorithm="EdDSA", headers={"typ": "JWT", "kid": kid})
                return httpx.Response(200, json=body, request=httpx.Request("POST", url))
            return response

    routing = RoutingHTTP()
    with TestClient(demo, base_url=config.origin) as client:
        demo.state.http = routing
        try:
            yield server, client, demo, routing, calls, path
        finally:
            # Remove only this test's dedicated client namespace keys.
            keys = list(server.store.scan_iter(FLOW_PREFIX + "*")) + list(server.store.scan_iter(SESSION_PREFIX + "*"))
            if keys:
                server.store.delete(*keys)


def begin(oidc_flow):
    server, client, *_ = oidc_flow
    response = client.get("/login", follow_redirects=False)
    assert response.status_code == 302
    query = parse_qs(urlsplit(response.headers["location"]).query)
    assert query["scope"] == ["openid"]
    assert query["code_challenge_method"] == ["S256"]
    authorized = server.client.get(response.headers["location"], follow_redirects=False)
    return authorized, query


def test_discovery_jwks_and_client_login(oidc_flow):
    server, client, demo, routing, calls, path = oidc_flow
    logged, _ = login(server)
    subject = logged.json()["user"]["id"]
    document = server.client.get("/.well-known/openid-configuration").json()
    assert document["issuer"] == "http://localhost"
    assert document["authorization_endpoint"] == "http://localhost/authorize"
    assert document["token_endpoint"] == "http://localhost/token"
    assert document["jwks_uri"] == "http://localhost/.well-known/jwks.json"
    assert "student:eligibility:read" in document["scopes_supported"]
    public = server.client.get(document["jwks_uri"])
    assert public.status_code == 200
    assert len(public.json()["keys"]) == 1
    assert all("d" not in key for key in public.json()["keys"])
    assert public.json() == FileKeyProvider(path).jwks()
    authorized, query = begin(oidc_flow)
    assert authorized.status_code == 302
    assert len(server.provider.posts) == 1  # No second Google authentication.
    result = client.get(authorized.headers["location"], follow_redirects=False)
    assert result.status_code == 302
    assert client.get("/me").json() == {"authenticated": True, "sub": subject}
    assert "aletheia_session" not in dict(client.cookies)
    cookie = result.headers["set-cookie"]
    assert "HttpOnly" in cookie and "SameSite=lax" in cookie
    record = json.loads(server.store.get(SESSION_PREFIX + fingerprint(client.cookies[SESSION_COOKIE])))
    assert set(record) == {"sub", "expires_at"}  # Tokens are discarded after validation.
    assert client.get(authorized.headers["location"], follow_redirects=False).status_code == 400
    assert client.post("/logout", headers={"Origin": "https://evil.example"}).status_code == 403
    logged_out = client.post("/logout", headers={"Origin": demo.state.settings.origin})
    assert logged_out.status_code == 204 and logged_out.content == b""
    assert client.get("/me").status_code == 401
    assert server.client.get("/auth/me").status_code == 200


@pytest.mark.parametrize("corrupt", ["nonce", "signature", "audience", "expired", "issuer", "kid", "type", "pkce"])
def test_client_refuses_invalid_tokens_and_pkce(oidc_flow, corrupt):
    server, client, _, routing, *_ = oidc_flow
    login(server)
    authorized, _ = begin(oidc_flow)
    routing.corrupt = corrupt
    result = client.get(authorized.headers["location"], follow_redirects=False)
    assert result.status_code == 400
    assert result.json() == {"detail": "OIDC login failed"}
    assert client.get("/me").status_code == 401
    assert SESSION_COOKIE not in dict(client.cookies)


@pytest.mark.parametrize("failure", ["state", "missing-cookie", "expired-flow", "identity-parameters", "duplicate-state", "error"])
def test_callback_state_browser_binding_and_input(oidc_flow, failure):
    server, client, _, _, calls, _ = oidc_flow
    login(server)
    authorized, _ = begin(oidc_flow)
    url = authorized.headers["location"]
    if failure == "state":
        query = parse_qs(urlsplit(url).query)
        url = "/callback?" + urlencode({"state": "wrong", "code": query["code"][0]})
    elif failure == "missing-cookie":
        client.cookies.clear()
    elif failure == "expired-flow":
        key = FLOW_PREFIX + fingerprint(client.cookies[FLOW_COOKIE])
        record = json.loads(server.store.get(key))
        record["expires_at"] = 0
        server.store.set(key, json.dumps(record))
    elif failure == "identity-parameters":
        url += "&user_id=attacker&email=trusted@example.edu"
    elif failure == "duplicate-state":
        url += "&state=duplicate"
    elif failure == "error":
        url += "&error=access_denied"
    assert client.get(url, follow_redirects=False).status_code == 400
    assert not any(method == "POST" for method, _ in calls)
    assert client.get("/me").status_code == 401


def test_external_consent_and_metadata_redirect_refused(oidc_flow):
    server, client, _, routing, calls, _ = oidc_flow
    login(server)
    with Session(server.engine) as session:
        session.get(SSOClient, "consumer").trust_level = TrustLevel.EXTERNAL
        session.commit()
    authorized, _ = begin(oidc_flow)
    assert authorized.status_code == 403
    assert authorized.json()["policy"] == "consent_required"
    assert client.get("/me").status_code == 401
    routing.corrupt = "discovery"
    assert client.get("/login", follow_redirects=False).status_code == 502
    assert not any("attacker" in url for _, url in calls)


def test_unconfigured_discovery_and_jwks(auth_flow):
    for path in ("/.well-known/jwks.json", "/.well-known/openid-configuration"):
        assert auth_flow.client.get(path).status_code == 503


def test_demo_store_outage_does_not_create_session(oidc_flow, monkeypatch):
    server, client, demo, *_ = oidc_flow
    async def fail(*args, **kwargs):
        raise RedisConnectionError("sensitive connection configuration")
    monkeypatch.setattr(demo.state.store, "set", fail)
    response = client.get("/login", follow_redirects=False)
    assert response.status_code == 503
    assert "sensitive" not in response.text
    assert SESSION_COOKIE not in dict(client.cookies)
