import base64
import hashlib
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from urllib.parse import quote_plus

import pytest
from sqlalchemy.orm import Session

from main import app
from models import ClientType, SSOClient, TrustLevel, User
from sso.authorization import CODE_PREFIX, context_fingerprint
from sso.token import TokenResponse
from test_authorization import (
    TEST_CHALLENGE,
    TEST_VERIFIER,
    auth_flow,
    authorize,
    issued_code,
    register,
)
from test_browser_session import login
from test_google_oauth import callback, flow, signing_key, start


class MockTokenIssuer:
    def __init__(self, should_fail: bool = False):
        self.calls = []
        self.should_fail = should_fail

    async def issue(self, user, client, scopes, nonce=None):
        if self.should_fail:
            raise RuntimeError("Simulated token issuer failure")
        self.calls.append({"user": user, "client": client, "scopes": scopes, "nonce": nonce})
        id_token = "mock-id-token" if "openid" in scopes else None
        return TokenResponse(
            access_token="mock-access-token",
            token_type="Bearer",
            expires_in=3600,
            id_token=id_token,
            scope=" ".join(scopes),
        )


@pytest.fixture
def mock_issuer(monkeypatch):
    issuer = MockTokenIssuer()
    monkeypatch.setattr(app.state, "token_issuer", issuer)
    return issuer


def basic_auth_header(client_id: str, secret: str) -> str:
    encoded = f"{quote_plus(client_id)}:{quote_plus(secret)}"
    return "Basic " + base64.b64encode(encoded.encode("utf-8")).decode("ascii")


def post_token(client, data: dict, headers: dict | None = None):
    req_headers = {"Content-Type": "application/x-www-form-urlencoded"}
    if headers:
        req_headers.update(headers)
    return client.post("/token", data=data, headers=req_headers)


def test_token_endpoint_without_configured_issuer_returns_503(auth_flow, monkeypatch):
    monkeypatch.setattr(app.state, "token_issuer", None)
    login(auth_flow)
    params = register(auth_flow)
    code = issued_code(authorize(auth_flow, params))

    response = post_token(
        auth_flow.client,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": params["redirect_uri"],
            "code_verifier": TEST_VERIFIER,
            "client_id": params["client_id"],
            "client_secret": "secret",
        },
    )
    assert response.status_code == 503
    assert response.json()["error"] == "temporarily_unavailable"
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["pragma"] == "no-cache"

    # Confirm the code is consumed and cannot be reused
    second_response = post_token(
        auth_flow.client,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": params["redirect_uri"],
            "code_verifier": TEST_VERIFIER,
            "client_id": params["client_id"],
            "client_secret": "secret",
        },
    )
    assert second_response.status_code == 400
    assert second_response.json()["error"] == "invalid_grant"


def test_token_exchange_success_confidential_with_basic_auth(auth_flow, mock_issuer):
    login(auth_flow)
    params = register(auth_flow)
    code = issued_code(authorize(auth_flow, params))

    headers = {"Authorization": basic_auth_header(params["client_id"], "secret")}
    response = post_token(
        auth_flow.client,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": params["redirect_uri"],
            "code_verifier": TEST_VERIFIER,
        },
        headers=headers,
    )
    assert response.status_code == 200
    body = response.json()
    assert body["access_token"] == "mock-access-token"
    assert body["token_type"] == "Bearer"
    assert body["expires_in"] == 3600
    assert body["id_token"] == "mock-id-token"
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["pragma"] == "no-cache"
    assert len(mock_issuer.calls) == 1
    assert mock_issuer.calls[0]["client"].client_id == params["client_id"]


def test_token_exchange_success_confidential_with_form_body(auth_flow, mock_issuer):
    login(auth_flow)
    params = register(auth_flow)
    code = issued_code(authorize(auth_flow, params))

    response = post_token(
        auth_flow.client,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": params["redirect_uri"],
            "code_verifier": TEST_VERIFIER,
            "client_id": params["client_id"],
            "client_secret": "secret",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["access_token"] == "mock-access-token"
    assert body["token_type"] == "Bearer"
    assert body["id_token"] == "mock-id-token"


def test_token_exchange_success_public_client(auth_flow, mock_issuer):
    login(auth_flow)
    params = register(auth_flow, client_type=ClientType.PUBLIC, secret_hash=None)
    code = issued_code(authorize(auth_flow, params))

    response = post_token(
        auth_flow.client,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": params["redirect_uri"],
            "code_verifier": TEST_VERIFIER,
            "client_id": params["client_id"],
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["access_token"] == "mock-access-token"
    assert body["token_type"] == "Bearer"


def test_token_exchange_without_openid_scope_omits_id_token(auth_flow, mock_issuer):
    login(auth_flow)
    params = register(auth_flow, allowed_scopes=["profile", "email"])
    params["scope"] = "profile email"
    code = issued_code(authorize(auth_flow, params))

    response = post_token(
        auth_flow.client,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": params["redirect_uri"],
            "code_verifier": TEST_VERIFIER,
            "client_id": params["client_id"],
            "client_secret": "secret",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert "id_token" not in body


def test_multiple_client_auth_mechanisms_rejected(auth_flow, mock_issuer):
    login(auth_flow)
    params = register(auth_flow)
    code = issued_code(authorize(auth_flow, params))

    headers = {"Authorization": basic_auth_header(params["client_id"], "secret")}
    # Sending client_id or client_secret in form while Basic Auth header is present
    response = post_token(
        auth_flow.client,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": params["redirect_uri"],
            "code_verifier": TEST_VERIFIER,
            "client_id": params["client_id"],
        },
        headers=headers,
    )
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_request"
    assert "Multiple client authentication mechanisms" in response.json()["error_description"]


def test_basic_auth_malformed_rejected(auth_flow, mock_issuer):
    login(auth_flow)
    params = register(auth_flow)
    code = issued_code(authorize(auth_flow, params))

    # Invalid base64
    response = post_token(
        auth_flow.client,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": params["redirect_uri"],
            "code_verifier": TEST_VERIFIER,
        },
        headers={"Authorization": "Basic !!!not-valid-base64!!!"},
    )
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_request"

    # Base64 without colon
    no_colon = base64.b64encode(b"just-username").decode("ascii")
    response2 = post_token(
        auth_flow.client,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": params["redirect_uri"],
            "code_verifier": TEST_VERIFIER,
        },
        headers={"Authorization": f"Basic {no_colon}"},
    )
    assert response2.status_code == 400
    assert response2.json()["error"] == "invalid_request"


def test_confidential_client_auth_failures(auth_flow, mock_issuer):
    login(auth_flow)
    params = register(auth_flow)
    code = issued_code(authorize(auth_flow, params))

    # Wrong secret via Basic Auth
    bad_headers = {"Authorization": basic_auth_header(params["client_id"], "wrong-secret")}
    res_bad_pw = post_token(
        auth_flow.client,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": params["redirect_uri"],
            "code_verifier": TEST_VERIFIER,
        },
        headers=bad_headers,
    )
    assert res_bad_pw.status_code == 401
    assert res_bad_pw.json()["error"] == "invalid_client"
    assert res_bad_pw.headers.get("www-authenticate") == 'Basic realm="Argus"'

    # Missing secret via Form Body
    res_no_sec = post_token(
        auth_flow.client,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": params["redirect_uri"],
            "code_verifier": TEST_VERIFIER,
            "client_id": params["client_id"],
        },
    )
    assert res_no_sec.status_code == 401
    assert res_no_sec.json()["error"] == "invalid_client"

    # Disabled client
    with Session(auth_flow.engine) as session:
        session.get(SSOClient, params["client_id"]).enabled = False
        session.commit()

    res_disabled = post_token(
        auth_flow.client,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": params["redirect_uri"],
            "code_verifier": TEST_VERIFIER,
            "client_id": params["client_id"],
            "client_secret": "secret",
        },
    )
    assert res_disabled.status_code == 401
    assert res_disabled.json()["error"] == "invalid_client"


def test_pkce_verification_failures(auth_flow, mock_issuer):
    login(auth_flow)
    params = register(auth_flow)
    code = issued_code(authorize(auth_flow, params))

    # Wrong code_verifier
    res_wrong_pkce = post_token(
        auth_flow.client,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": params["redirect_uri"],
            "code_verifier": "w" * 64,
            "client_id": params["client_id"],
            "client_secret": "secret",
        },
    )
    assert res_wrong_pkce.status_code == 400
    assert res_wrong_pkce.json()["error"] == "invalid_grant"

    # Missing code_verifier
    res_no_pkce = post_token(
        auth_flow.client,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": params["redirect_uri"],
            "client_id": params["client_id"],
            "client_secret": "secret",
        },
    )
    assert res_no_pkce.status_code == 400
    assert res_no_pkce.json()["error"] == "invalid_request"

    # Malformed code_verifier (too short)
    res_short = post_token(
        auth_flow.client,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": params["redirect_uri"],
            "code_verifier": "short",
            "client_id": params["client_id"],
            "client_secret": "secret",
        },
    )
    assert res_short.status_code == 400
    assert res_short.json()["error"] == "invalid_request"


def test_code_single_use_and_second_use_rejected(auth_flow, mock_issuer):
    login(auth_flow)
    params = register(auth_flow)
    code = issued_code(authorize(auth_flow, params))

    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": params["redirect_uri"],
        "code_verifier": TEST_VERIFIER,
        "client_id": params["client_id"],
        "client_secret": "secret",
    }
    first = post_token(auth_flow.client, data)
    assert first.status_code == 200

    second = post_token(auth_flow.client, data)
    assert second.status_code == 400
    assert second.json()["error"] == "invalid_grant"


def test_expired_code_rejected(auth_flow, mock_issuer):
    login(auth_flow)
    params = register(auth_flow)
    code = issued_code(authorize(auth_flow, params))

    auth_flow.store.pexpire(CODE_PREFIX + context_fingerprint(code), 50)
    time.sleep(0.1)

    response = post_token(
        auth_flow.client,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": params["redirect_uri"],
            "code_verifier": TEST_VERIFIER,
            "client_id": params["client_id"],
            "client_secret": "secret",
        },
    )
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"


def test_atomic_concurrent_exchange(auth_flow, mock_issuer):
    login(auth_flow)
    params = register(auth_flow)
    code = issued_code(authorize(auth_flow, params))

    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": params["redirect_uri"],
        "code_verifier": TEST_VERIFIER,
        "client_id": params["client_id"],
        "client_secret": "secret",
    }

    def do_exchange(_):
        return post_token(auth_flow.client, data).status_code

    with ThreadPoolExecutor(max_workers=2) as pool:
        statuses = sorted(pool.map(do_exchange, range(2)))
    assert statuses == [200, 400]


def test_mismatched_client_or_redirect_uri_does_not_burn_code(auth_flow, mock_issuer):
    login(auth_flow)
    params = register(auth_flow)
    code = issued_code(authorize(auth_flow, params))

    # Mismatched redirect_uri
    bad_uri_res = post_token(
        auth_flow.client,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "https://evil.example/callback",
            "code_verifier": TEST_VERIFIER,
            "client_id": params["client_id"],
            "client_secret": "secret",
        },
    )
    assert bad_uri_res.status_code == 400
    assert bad_uri_res.json()["error"] == "invalid_grant"

    # Now redeem with legitimate parameters -> must succeed
    legit_res = post_token(
        auth_flow.client,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": params["redirect_uri"],
            "code_verifier": TEST_VERIFIER,
            "client_id": params["client_id"],
            "client_secret": "secret",
        },
    )
    assert legit_res.status_code == 200


def test_issuer_failure_consumes_code_permanently(auth_flow, monkeypatch):
    failing_issuer = MockTokenIssuer(should_fail=True)
    monkeypatch.setattr(app.state, "token_issuer", failing_issuer)

    login(auth_flow)
    params = register(auth_flow)
    code = issued_code(authorize(auth_flow, params))

    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": params["redirect_uri"],
        "code_verifier": TEST_VERIFIER,
        "client_id": params["client_id"],
        "client_secret": "secret",
    }

    # Fails at token issuance
    failed_res = post_token(auth_flow.client, data)
    assert failed_res.status_code == 503
    assert failed_res.json()["error"] == "temporarily_unavailable"

    # Code MUST NOT be restored
    second_attempt = post_token(auth_flow.client, data)
    assert second_attempt.status_code == 400
    assert second_attempt.json()["error"] == "invalid_grant"


def test_disabled_user_fails_and_consumes_code(auth_flow, mock_issuer):
    user_res, _ = login(auth_flow)
    user_id = user_res.json()["user"]["id"]

    params = register(auth_flow)
    code = issued_code(authorize(auth_flow, params))

    # Disable the user in DB
    with Session(auth_flow.engine) as session:
        user = session.get(User, user_id)
        user.disabled_at = datetime.now(timezone.utc)
        session.commit()

    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": params["redirect_uri"],
        "code_verifier": TEST_VERIFIER,
        "client_id": params["client_id"],
        "client_secret": "secret",
    }
    res = post_token(auth_flow.client, data)
    assert res.status_code == 400
    assert res.json()["error"] == "invalid_grant"

    # Confirm code cannot be used again
    res_retry = post_token(auth_flow.client, data)
    assert res_retry.status_code == 400
    assert res_retry.json()["error"] == "invalid_grant"


def test_unsupported_grant_type(auth_flow, mock_issuer):
    login(auth_flow)
    params = register(auth_flow)

    res = post_token(
        auth_flow.client,
        {
            "grant_type": "password",
            "code": "any-code",
            "redirect_uri": params["redirect_uri"],
            "code_verifier": TEST_VERIFIER,
            "client_id": params["client_id"],
            "client_secret": "secret",
        },
    )
    assert res.status_code == 400
    assert res.json()["error"] == "unsupported_grant_type"


def test_missing_required_parameters(auth_flow, mock_issuer):
    login(auth_flow)
    params = register(auth_flow)

    # Missing grant_type
    res1 = post_token(auth_flow.client, {"code": "code", "redirect_uri": "uri"})
    assert res1.status_code == 400
    assert res1.json()["error"] == "invalid_request"

    # Missing code
    res2 = post_token(auth_flow.client, {"grant_type": "authorization_code", "redirect_uri": "uri"})
    assert res2.status_code == 400
    assert res2.json()["error"] == "invalid_request"

    # Missing redirect_uri
    res3 = post_token(auth_flow.client, {"grant_type": "authorization_code", "code": "code"})
    assert res3.status_code == 400
    assert res3.json()["error"] == "invalid_request"


def test_duplicate_parameters_rejected(auth_flow, mock_issuer):
    login(auth_flow)
    params = register(auth_flow)
    code = issued_code(authorize(auth_flow, params))

    raw_body = (
        f"grant_type=authorization_code&code={code}&redirect_uri={quote_plus(params['redirect_uri'])}"
        f"&code_verifier={TEST_VERIFIER}&client_id={params['client_id']}&client_secret=secret&code=second-code"
    )
    res = auth_flow.client.post(
        "/token",
        content=raw_body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert res.status_code == 400
    assert res.json()["error"] == "invalid_request"
    assert "Duplicate parameter" in res.json()["error_description"]


def test_invalid_content_type_rejected(auth_flow, mock_issuer):
    res = auth_flow.client.post("/token", json={"grant_type": "authorization_code"})
    assert res.status_code == 400
    assert res.json()["error"] == "invalid_request"
    assert "Content-Type must be application/x-www-form-urlencoded" in res.json()["error_description"]


def test_openapi_schema_contains_token_endpoint(auth_flow):
    res = auth_flow.client.get("/openapi.json")
    assert res.status_code == 200
    schema = res.json()
    assert "/token" in schema["paths"]
    token_path = schema["paths"]["/token"]
    assert "post" in token_path
    post_op = token_path["post"]
    assert "Argus SSO" in post_op["tags"]
    responses = post_op["responses"]
    assert "200" in responses
    assert "400" in responses
    assert "401" in responses
    assert "503" in responses
