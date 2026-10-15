import asyncio
import uuid
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from alembic import command
from sqlalchemy import inspect
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from main import app
from models import EligibilityStatus, SSOClient, StudentEligibility, User, VerificationStatus
from student.eligibility import SCOPE, decide
from test_authorization import authorize, issued_code
from test_browser_session import login
from test_oidc_integration import oidc_flow
from test_authorization import auth_flow
from test_google_oauth import flow, signing_key


def evidence(**changes):
    now = datetime.now(timezone.utc)
    return StudentEligibility(user_id=uuid.uuid4(), status=EligibilityStatus.ELIGIBLE,
                              source="test_fixture", verification_status=VerificationStatus.TEST,
                              updated_at=changes.pop("updated_at", now),
                              valid_until=changes.pop("valid_until", now + timedelta(hours=1)), **changes)


@pytest.mark.parametrize("status", list(EligibilityStatus))
def test_test_data_is_explicitly_unverified(status):
    item = evidence()
    item.status = status
    result = decide(item)
    assert result.status == status
    assert result.source == "test_fixture" and result.verified is False


def test_missing_expired_unverified_or_future_evidence_is_unknown():
    assert decide(None).status == EligibilityStatus.UNKNOWN
    now = datetime.now(timezone.utc)
    cases = [evidence(updated_at=now - timedelta(days=1), valid_until=now - timedelta(seconds=1)),
             evidence(valid_until=None), evidence(updated_at=now + timedelta(seconds=1))]
    unverified = evidence()
    unverified.source, unverified.verification_status = "registrar", VerificationStatus.UNVERIFIED
    cases.append(unverified)
    for item in cases:
        result = decide(item, now)
        assert result.status == EligibilityStatus.UNKNOWN
        assert not result.verified
    official = evidence()
    official.source, official.verification_status = "registrar", VerificationStatus.VERIFIED
    assert decide(official).verified


def provision(oidc_flow, scopes=None):
    server = oidc_flow[0]
    logged, _ = login(server)
    user_id = uuid.UUID(logged.json()["user"]["id"])
    with Session(server.engine) as session:
        client = session.get(SSOClient, "consumer")
        client.allowed_scopes = ["openid", SCOPE]
        session.commit()
    verifier = "v" * 64
    import base64
    import hashlib
    params = {"response_type": "code", "client_id": "consumer", "redirect_uri": "http://127.0.0.1:8001/callback",
              "scope": " ".join(scopes or ["openid", SCOPE]), "code_challenge_method": "S256",
              "code_challenge": base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()}
    code = issued_code(authorize(server, params))
    response = server.client.post("/token", data={
        "grant_type": "authorization_code", "code": code, "redirect_uri": params["redirect_uri"],
        "code_verifier": verifier, "client_id": "consumer", "client_secret": "secret",
    })
    assert response.status_code == 200
    return user_id, response.json()


def get(server, token, query=""):
    return server.client.get("/api/v1/student/eligibility" + query, headers={"Authorization": "Bearer " + token})


def test_api_no_login_or_email_inference_and_minimal_test_response(oidc_flow):
    server = oidc_flow[0]
    user_id, tokens = provision(oidc_flow)
    # Google login classified s1234567@school.edu as student; this proves no enrollment.
    assert get(server, tokens["access_token"]).json()["status"] == "unknown"
    with Session(server.engine) as session:
        item = evidence()
        item.user_id = user_id
        session.add(item)
        session.commit()
    response = get(server, tokens["access_token"])
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "eligible" and body["source"] == "test_fixture"
    assert body["verified"] is False and body["verification_status"] == "test"
    assert set(body) == {"status", "source", "verified", "verification_status", "updated_at", "valid_until"}
    assert response.headers["cache-control"] == "no-store"
    assert get(server, tokens["access_token"], "?user_id=" + str(uuid.uuid4())).status_code == 400
    with Session(server.engine) as session:
        session.get(StudentEligibility, user_id).status = EligibilityStatus.INELIGIBLE
        session.commit()
    assert get(server, tokens["access_token"]).json()["status"] == "ineligible"
    with Session(server.engine) as session:
        item = session.get(StudentEligibility, user_id)
        item.updated_at = datetime.now(timezone.utc) - timedelta(hours=2)
        item.valid_until = datetime.now(timezone.utc) - timedelta(hours=1)
        session.commit()
    assert get(server, tokens["access_token"]).json()["status"] == "unknown"
    assert get(server, tokens["access_token"]).json()["verified"] is False


def test_api_requires_bearer_scope_and_current_client_authorization(oidc_flow):
    server = oidc_flow[0]
    user_id, tokens = provision(oidc_flow, ["openid"])
    assert server.client.get("/api/v1/student/eligibility").status_code == 401  # Cookie is insufficient.
    response = get(server, tokens["access_token"])
    assert response.status_code == 403 and "insufficient_scope" in response.headers["www-authenticate"]
    assert response.headers["cache-control"] == "no-store"
    assert get(server, tokens["id_token"]).status_code == 401
    with Session(server.engine) as session:
        user, client = session.get(User, user_id), session.get(SSOClient, "consumer")
        valid = asyncio.run(app.state.token_issuer.issue(user, client, [SCOPE])).access_token
        client.allowed_scopes = ["openid"]
        session.commit()
    assert get(server, valid).status_code == 403
    with Session(server.engine) as session:
        session.get(SSOClient, "consumer").enabled = False
        session.commit()
    assert get(server, valid).status_code == 401


@pytest.mark.parametrize("failure", ["audience", "issuer", "expired", "signature", "kid", "disabled-user", "deleted-user"])
def test_api_rejects_invalid_identity_or_token(oidc_flow, failure):
    server = oidc_flow[0]
    user_id, tokens = provision(oidc_flow)
    token = tokens["access_token"]
    if failure in {"disabled-user", "deleted-user"}:
        with Session(server.engine) as session:
            user = session.get(User, user_id)
            if failure == "disabled-user":
                user.disabled_at = datetime.now(timezone.utc)
            else:
                session.delete(user)
            session.commit()
    else:
        claims = jwt.decode(token, options={"verify_signature": False})
        kid, key = app.state.token_issuer.keys.signing_key("sso")
        if failure == "audience":
            claims["aud"] = "another-resource"
        elif failure == "issuer":
            claims["iss"] = "https://other.example"
        elif failure == "expired":
            claims["exp"] = 0
        elif failure == "signature":
            from signing_keys import SigningKey
            key = SigningKey.generate("sso").private
        elif failure == "kid":
            kid = "unknown"
        token = jwt.encode(claims, key, algorithm="EdDSA", headers={"typ": "at+jwt", "kid": kid})
    response = get(server, token)
    assert response.status_code == 401
    assert "invalid_token" in response.headers["www-authenticate"]


def test_eligibility_migration_constraints_cascade_and_openapi(oidc_flow):
    server = oidc_flow[0]
    user_id, tokens = provision(oidc_flow)
    command.check(server.config)
    with Session(server.engine) as session:
        item = evidence()
        item.user_id = user_id
        item.verification_status = VerificationStatus.VERIFIED
        session.add(item)
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()
        item = evidence()
        item.user_id = user_id
        session.add(item)
        session.commit()
        session.delete(session.get(User, user_id))
        session.commit()
        assert session.get(StudentEligibility, user_id) is None
    schema = server.client.get("/openapi.json").json()
    operation = schema["paths"]["/api/v1/student/eligibility"]["get"]
    assert operation["security"] == [{"HTTPBearer": []}]
    command.downgrade(server.config, "20261015_0006")
    assert "student_eligibility" not in inspect(server.engine).get_table_names()
    command.upgrade(server.config, "head")


def test_key_store_outage_is_unavailable_without_leaking_material(oidc_flow):
    server, _, _, _, _, path = oidc_flow
    _, tokens = provision(oidc_flow)
    path.write_text("sensitive-broken-key-configuration")
    for response in (get(server, tokens["access_token"]), server.client.get("/.well-known/jwks.json")):
        assert response.status_code == 503
        assert "sensitive-broken" not in response.text
        assert response.headers["cache-control"] == "no-store"
