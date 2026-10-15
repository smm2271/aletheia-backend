import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import pytest
from alembic import command
from sqlalchemy import func, inspect, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from main import app
from models import QRCredential, User
from auth import session as browser_session
from routes import qr as qr_routes
from signing_keys import FileKeyProvider, save_key_file
from test_browser_session import login
from test_oidc_integration import oidc_flow
from test_authorization import auth_flow
from test_google_oauth import callback, flow, signing_key, start

PATH = "/api/v1/qr/credentials"
ORIGIN = {"Origin": "http://localhost"}


def issue(server, **kwargs):
    return server.client.post(PATH, headers=ORIGIN, **kwargs)


def test_self_issue_and_idempotent_response(oidc_flow):
    server = oidc_flow[0]
    response, _ = login(server)
    user_id = uuid.UUID(response.json()["user"]["id"])
    first = issue(server)
    assert first.status_code == 200
    assert first.headers["cache-control"] == "no-store"
    assert first.headers["pragma"] == "no-cache"
    assert "set-cookie" not in first.headers
    body = first.json()
    assert set(body) == {"token", "credential_id", "format_version", "issued_at", "expires_at"}
    claims = app.state.qr_issuer.validate(body["token"])
    assert claims["cid"] == body["credential_id"] and body["format_version"] == 1
    assert str(user_id) not in first.text
    assert issue(server, json={}).json() == body
    with Session(server.engine) as session:
        assert session.scalar(select(func.count()).select_from(QRCredential)) == 1
        assert session.get(QRCredential, user_id).credential_id == claims["cid"]
    assert server.client.get("/auth/me").status_code == 200


def test_no_session_csrf_disabled_users_or_arbitrary_subjects(oidc_flow):
    server = oidc_flow[0]
    assert issue(server).status_code == 401
    response, _ = login(server)
    user_id = uuid.UUID(response.json()["user"]["id"])
    assert server.client.post(PATH).status_code == 403
    assert server.client.post(PATH, headers={"Origin": "https://evil.example"}).status_code == 403
    assert issue(server, json={"user_id": str(uuid.uuid4())}).status_code == 422
    assert issue(server, params={"user_id": str(uuid.uuid4())}).status_code == 400
    with Session(server.engine) as session:
        assert session.scalar(select(func.count()).select_from(QRCredential)) == 0
        session.get(User, user_id).disabled_at = datetime.now(timezone.utc)
        session.commit()
    assert issue(server).status_code == 401


def test_concurrent_first_issuance_is_one_credential(oidc_flow):
    server = oidc_flow[0]
    login(server)
    with ThreadPoolExecutor(max_workers=4) as pool:
        responses = list(pool.map(lambda _: issue(server), range(4)))
    assert [r.status_code for r in responses] == [200] * 4
    assert len({r.json()["token"] for r in responses}) == 1
    with Session(server.engine) as session:
        assert session.scalar(select(func.count()).select_from(QRCredential)) == 1


def test_different_users_have_independent_credentials(oidc_flow):
    server = oidc_flow[0]
    login(server)
    first = issue(server).json()
    query = start(server, sub="second-subject", email="second@school.edu")
    assert callback(server, query["state"][0]).status_code == 200
    second = issue(server).json()
    assert second["credential_id"] != first["credential_id"]
    assert second["token"] != first["token"]
    assert issue(server).json() == second
    with Session(server.engine) as session:
        assert session.scalar(select(func.count()).select_from(QRCredential)) == 2


def test_concurrent_expired_issuance_replaces_only_once(oidc_flow):
    server = oidc_flow[0]
    response, _ = login(server)
    user_id = uuid.UUID(response.json()["user"]["id"])
    first = issue(server).json()
    with Session(server.engine) as session:
        row = session.get(QRCredential, user_id)
        row.issued_at = datetime.now(timezone.utc) - timedelta(hours=2)
        row.expires_at = datetime.now(timezone.utc) - timedelta(hours=1)
        session.commit()
    with ThreadPoolExecutor(max_workers=4) as pool:
        responses = list(pool.map(lambda _: issue(server), range(4)))
    assert [r.status_code for r in responses] == [200] * 4
    assert len({r.json()["token"] for r in responses}) == 1
    assert responses[0].json()["credential_id"] != first["credential_id"]
    with Session(server.engine) as session:
        assert session.scalar(select(func.count()).select_from(QRCredential)) == 1


def test_expiry_replaces_mapping_but_not_before_deadline(oidc_flow):
    server = oidc_flow[0]
    response, _ = login(server)
    user_id = uuid.UUID(response.json()["user"]["id"])
    first = issue(server).json()
    with Session(server.engine) as session:
        row = session.get(QRCredential, user_id)
        row.issued_at = datetime.now(timezone.utc) - timedelta(hours=2)
        row.expires_at = datetime.now(timezone.utc) - timedelta(hours=1)
        session.commit()
    second = issue(server).json()
    assert second["credential_id"] != first["credential_id"]
    assert second["token"] != first["token"]
    with Session(server.engine) as session:
        assert session.scalar(select(func.count()).select_from(QRCredential)) == 1
        assert session.get(QRCredential, user_id).credential_id == second["credential_id"]


def test_key_rotation_reuses_existing_signed_token(oidc_flow):
    server, _, _, _, _, path = oidc_flow
    login(server)
    old = issue(server).json()
    rotated = FileKeyProvider(path).snapshot().rotate("qr")
    save_key_file(path, rotated)
    assert issue(server).json() == old
    assert app.state.qr_issuer.validate(old["token"])


def test_invalid_active_record_is_not_an_unlimited_reissue_escape(oidc_flow):
    server, _, _, _, _, path = oidc_flow
    response, _ = login(server)
    user_id = uuid.UUID(response.json()["user"]["id"])
    first = issue(server).json()
    with Session(server.engine) as session:
        session.get(QRCredential, user_id).token = first["token"] + "tampered"
        session.commit()
    assert issue(server).status_code == 409
    with Session(server.engine) as session:
        assert session.scalar(select(func.count()).select_from(QRCredential)) == 1


@pytest.mark.parametrize("field", ["credential_id", "issued_at", "expires_at"])
def test_valid_token_with_mismatched_mapping_is_not_returned(oidc_flow, field):
    server = oidc_flow[0]
    response, _ = login(server)
    user_id = uuid.UUID(response.json()["user"]["id"])
    first = issue(server).json()
    with Session(server.engine) as session:
        row = session.get(QRCredential, user_id)
        if field == "credential_id":
            row.credential_id = "a" * 43
        else:
            setattr(row, field, getattr(row, field) + timedelta(seconds=1))
        session.commit()
    response = issue(server)
    assert response.status_code == 409
    assert first["token"] not in response.text
    assert response.headers["cache-control"] == "no-store"


@pytest.mark.parametrize("stage", ["authentication", "issuance"])
def test_database_failure_is_unavailable_without_details(oidc_flow, monkeypatch, stage):
    server = oidc_flow[0]
    login(server)
    def unavailable(*args, **kwargs):
        raise SQLAlchemyError("sensitive database connection details")
    target, name = ((browser_session, "load_user") if stage == "authentication"
                    else (qr_routes, "get_or_issue"))
    monkeypatch.setattr(target, name, unavailable)
    response = issue(server)
    assert response.status_code == 503
    assert "sensitive" not in response.text
    assert response.headers["cache-control"] == "no-store"


def test_deleted_user_cannot_obtain_previous_credential(oidc_flow):
    server = oidc_flow[0]
    response, _ = login(server)
    user_id = uuid.UUID(response.json()["user"]["id"])
    assert issue(server).status_code == 200
    with Session(server.engine) as session:
        session.delete(session.get(User, user_id))
        session.commit()
    response = issue(server)
    assert response.status_code == 401
    assert response.headers["cache-control"] == "no-store"
    with Session(server.engine) as session:
        assert session.scalar(select(func.count()).select_from(QRCredential)) == 0


@pytest.mark.parametrize("change", ["disable", "delete"])
def test_user_state_is_rechecked_after_authentication(oidc_flow, monkeypatch, change):
    server = oidc_flow[0]
    response, _ = login(server)
    user_id = uuid.UUID(response.json()["user"]["id"])
    # Simulate the user changing after authentication but before the issuance lock.
    with Session(server.engine) as session:
        stale_user = session.get(User, user_id)
        session.expunge(stale_user)
        current = session.get(User, user_id)
        if change == "disable":
            current.disabled_at = datetime.now(timezone.utc)
        else:
            session.delete(current)
        session.commit()
    async def authenticated_before_change(request):
        return stale_user
    monkeypatch.setattr(qr_routes, "get_current_user", authenticated_before_change)
    response = issue(server)
    assert response.status_code == 401
    assert response.headers["cache-control"] == "no-store"
    with Session(server.engine) as session:
        assert session.scalar(select(func.count()).select_from(QRCredential)) == 0


def test_unconfigured_or_unavailable_keys(oidc_flow, monkeypatch):
    server, _, _, _, _, path = oidc_flow
    login(server)
    issuer = app.state.qr_issuer
    monkeypatch.setattr(app.state, "qr_issuer", None)
    assert issue(server).status_code == 503
    monkeypatch.setattr(app.state, "qr_issuer", issuer)
    path.write_text("sensitive-invalid-config")
    response = issue(server)
    assert response.status_code == 503 and "sensitive" not in response.text
    assert response.headers["cache-control"] == "no-store"


def test_credential_migration_constraints_cascade_and_openapi(oidc_flow):
    server = oidc_flow[0]
    response, _ = login(server)
    user_id = uuid.UUID(response.json()["user"]["id"])
    token = issue(server).json()["token"]
    command.check(server.config)
    with Session(server.engine) as session:
        original = session.get(QRCredential, user_id)
        assert original.token == token
        original.expires_at = original.issued_at
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()
        session.delete(session.get(User, user_id))
        session.commit()
        assert session.get(QRCredential, user_id) is None
    schema = server.client.get("/openapi.json").json()
    operation = schema["paths"][PATH]["post"]
    assert "APIKeyCookie" in operation["security"][0]
    assert {"200", "400", "401", "403", "409", "422", "503"}.issubset(operation["responses"])
    assert "user_id" not in schema["components"]["schemas"]["CredentialRequest"].get("properties", {})
    command.downgrade(server.config, "20261015_0007")
    assert "qr_credentials" not in inspect(server.engine).get_table_names()
    command.upgrade(server.config, "head")
