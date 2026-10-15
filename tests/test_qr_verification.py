import asyncio
import time
import uuid
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError

from main import app
from models import QRCredential, SSOClient, User
from qr import verification
from qr.tokens import TOKEN_TYPE
from qr.verification import SCOPE
from signing_keys import KeyManagementError
from test_browser_session import login
from test_google_oauth import callback, flow, signing_key, start
from test_authorization import auth_flow
from test_oidc_integration import oidc_flow

PATH = "/api/v1/qr/static/verify"


@pytest.fixture
def scanner(oidc_flow):
    server = oidc_flow[0]
    response, _ = login(server)
    scanner_id = uuid.UUID(response.json()["user"]["id"])
    with Session(server.engine) as session:
        client = session.get(SSOClient, "consumer")
        client.allowed_scopes = ["openid", SCOPE]
        session.commit()
        user = session.get(User, scanner_id)
        tokens = asyncio.run(app.state.token_issuer.issue(user, client, ["openid", SCOPE]))
    query = start(server, sub="scanned-subject", email="scanned@school.edu")
    response = callback(server, query["state"][0])
    assert response.status_code == 200
    owner_id = uuid.UUID(response.json()["user"]["id"])
    response = server.client.post("/api/v1/qr/credentials", headers={"Origin": "http://localhost"})
    assert response.status_code == 200
    return server, scanner_id, owner_id, tokens, response.json()["token"]


def verify(scanner, token=None, access=None, **kwargs):
    server, _, _, tokens, qr = scanner
    response = server.client.post(PATH, headers={"Authorization": "Bearer " + (access or tokens.access_token)},
                                  json={"token": qr if token is None else token}, **kwargs)
    assert response.headers["cache-control"] == "no-store"
    return response


def resign(token, purpose, *, changes=None, headers=None):
    claims = jwt.decode(token, options={"verify_signature": False})
    claims.update(changes or {})
    issuer = app.state.token_issuer if purpose == "sso" else app.state.qr_issuer
    kid, key = issuer.keys.signing_key(purpose)
    header = jwt.get_unverified_header(token)
    header.update({"kid": kid, **(headers or {})})
    return jwt.encode(claims, key, algorithm="EdDSA", headers=header)


def test_valid_response_is_minimal_and_does_not_authorize_entry(scanner):
    server, scanner_id, owner_id, _, qr = scanner
    assert scanner_id != owner_id
    response = verify(scanner)
    assert response.status_code == 200 and response.json() == {"valid": True}
    assert response.headers["pragma"] == "no-cache"
    assert qr not in response.text and str(owner_id) not in response.text
    assert verify(scanner).json() == {"valid": True}  # Nonce policy is added separately.
    operation = server.client.get("/openapi.json").json()["paths"][PATH]["post"]
    assert "HTTPBearer" in operation["security"][0]
    assert {"200", "400", "401", "403", "422", "503"}.issubset(operation["responses"])
    assert SCOPE in server.client.get("/.well-known/openid-configuration").json()["scopes_supported"]


@pytest.mark.parametrize("authorization", [None, "Basic secret", "Bearer", "Bearer invalid", "Bearer one two"])
def test_browser_session_is_not_scanner_authorization(scanner, authorization):
    server, *_, qr = scanner
    response = server.client.post(PATH, json={"token": qr},
                                  headers={"Authorization": authorization} if authorization else {})
    assert response.status_code == 401
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["www-authenticate"].startswith("Bearer")


@pytest.mark.parametrize("kind", ["id", "qr"])
def test_id_and_qr_tokens_cannot_be_scanner_bearer(scanner, kind):
    token = scanner[3].id_token if kind == "id" else scanner[4]
    assert verify(scanner, access=token).status_code == 401


@pytest.mark.parametrize("changes,headers", [
    ({"aud": "another-resource"}, {}), ({"iss": "https://evil.example"}, {}),
    ({"exp": int(time.time()) - 1, "iat": int(time.time()) - 20}, {}),
    ({}, {"kid": "unknown"}), ({"token_use": "id_token"}, {}), ({}, {"typ": "JWT"}),
])
def test_scanner_access_token_claims_and_keys_are_verified(scanner, changes, headers):
    token = resign(scanner[3].access_token, "sso", changes=changes, headers=headers)
    assert verify(scanner, access=token).status_code == 401


def test_access_scope_is_required(scanner):
    token = resign(scanner[3].access_token, "sso", changes={"scope": "openid"})
    response = verify(scanner, access=token)
    assert response.status_code == 403
    assert SCOPE in response.headers["www-authenticate"]


def test_scanner_access_token_signature_is_verified(scanner):
    token = scanner[3].access_token
    tampered = token[:-8] + ("AAAAAAAA" if token[-8:] != "AAAAAAAA" else "BBBBBBBB")
    assert verify(scanner, access=tampered).status_code == 401


@pytest.mark.parametrize("change", ["scanner_disabled", "scanner_deleted", "client_disabled", "client_deleted", "scope_removed"])
def test_live_scanner_and_client_authorization_is_rechecked(scanner, change):
    server, scanner_id, *_ = scanner
    with Session(server.engine) as session:
        user = session.get(User, scanner_id)
        client = session.get(SSOClient, "consumer")
        if change == "scanner_disabled":
            user.disabled_at = datetime.now(timezone.utc)
        elif change == "scanner_deleted":
            session.delete(user)
        elif change == "client_disabled":
            client.enabled = False
        elif change == "client_deleted":
            session.delete(client)
        else:
            client.allowed_scopes = ["openid"]
        session.commit()
    assert verify(scanner).status_code == (403 if change == "scope_removed" else 401)


@pytest.mark.parametrize("changes,headers", [
    ({"aud": "another-resource"}, {}), ({"iss": "https://evil.example"}, {}),
    ({"purpose": "access_token"}, {}), ({"ver": 2}, {}),
    ({"exp": int(time.time()) - 1, "iat": int(time.time()) - 20}, {}),
    ({}, {"kid": "unknown"}), ({}, {"typ": "at+jwt"}),
])
def test_qr_claim_failures_are_generic(scanner, changes, headers):
    token = resign(scanner[4], "qr", changes=changes, headers=headers)
    response = verify(scanner, token=token)
    assert response.status_code == 400 and response.json() == {"detail": "Invalid QR credential"}


@pytest.mark.parametrize("kind", ["access", "id", "malformed", "signature", "unmapped"])
def test_qr_type_signature_and_mapping_are_required(scanner, kind):
    token = {"access": scanner[3].access_token, "id": scanner[3].id_token,
             "malformed": "invalid", "signature": scanner[4][:-8] + "AAAAAAAA",
             "unmapped": app.state.qr_issuer.issue()[0]}[kind]
    response = verify(scanner, token=token)
    assert response.status_code == 400 and response.json() == {"detail": "Invalid QR credential"}


@pytest.mark.parametrize("change", ["disabled", "deleted", "mapping_deleted", "mapping_replaced", "token", "issued_at", "expires_at", "expired", "fractional_time"])
def test_current_mapping_owner_and_metadata_are_required(scanner, change):
    server, _, owner_id, *_ = scanner
    with Session(server.engine) as session:
        row = session.get(QRCredential, owner_id)
        user = session.get(User, owner_id)
        if change == "disabled":
            user.disabled_at = datetime.now(timezone.utc)
        elif change == "deleted":
            session.delete(user)
        elif change == "mapping_deleted":
            session.delete(row)
        elif change == "mapping_replaced":
            row.token, claims = app.state.qr_issuer.issue()
            row.credential_id = claims["cid"]
        elif change == "token":
            row.token = "corrupt stored token with unicode 學生"
        elif change == "expired":
            row.issued_at = datetime.now(timezone.utc) - timedelta(hours=2)
            row.expires_at = datetime.now(timezone.utc) - timedelta(hours=1)
        elif change == "fractional_time":
            row.issued_at += timedelta(microseconds=1)
        else:
            setattr(row, change, getattr(row, change) + timedelta(seconds=1))
        session.commit()
    response = verify(scanner)
    assert response.status_code == 400 and response.json() == {"detail": "Invalid QR credential"}


@pytest.mark.parametrize("body", [{}, {"token": ""}, {"token": 123}, {"token": "sensitive" * 200},
                                  {"token": "sensitive", "user_id": "private"}, None])
def test_request_validation_is_no_store_and_does_not_reflect_credentials(scanner, body):
    server = scanner[0]
    response = server.client.post(PATH, headers={"Authorization": "Bearer " + scanner[3].access_token}, json=body)
    assert response.status_code == 422
    assert response.headers["cache-control"] == "no-store"
    assert response.json() == {"detail": "Invalid verification request"}


def test_query_parameters_are_rejected(scanner):
    assert verify(scanner, params={"user_id": "arbitrary"}).status_code == 400


@pytest.mark.parametrize("kind", ["database", "sso_key", "qr_key", "unconfigured"])
def test_dependency_failures_are_unavailable_and_do_not_expose_details(scanner, monkeypatch, kind):
    def fail(*args, **kwargs):
        error = SQLAlchemyError if kind == "database" else KeyManagementError
        raise error("sensitive infrastructure detail")
    if kind == "database":
        monkeypatch.setattr(verification, "verify_mapping", fail)
    elif kind == "sso_key":
        monkeypatch.setattr(app.state.token_issuer.keys, "verification_key", fail)
    elif kind == "qr_key":
        # Both issuers normally share a provider; isolate the QR failure from SSO.
        class BrokenQRKeys:
            verification_key = staticmethod(fail)
        monkeypatch.setattr(app.state.qr_issuer, "keys", BrokenQRKeys())
    else:
        monkeypatch.setattr(app.state, "qr_issuer", None)
    response = verify(scanner)
    assert response.status_code == 503 and "sensitive" not in response.text


def test_qr_purpose_is_not_sso_even_when_header_matches(scanner):
    token = resign(scanner[3].access_token, "sso", headers={"typ": TOKEN_TYPE})
    assert verify(scanner, token=token).status_code == 400
