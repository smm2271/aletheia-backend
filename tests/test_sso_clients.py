import uuid

import pytest
from alembic import command
from fastapi import HTTPException
from sqlalchemy import inspect, select
from sqlalchemy.orm import Session

from admin.bootstrap import set_admin
from models import SSOClient, User
from sso.clients import validate_client_request, verify_client_secret
from test_browser_session import login
from test_google_oauth import flow, signing_key

BASE = "/api/v1/admin/clients"
ORIGIN = {"Origin": "http://localhost"}


def admin_login(flow):
    response, _ = login(flow)
    set_admin(flow.engine, uuid.UUID(response.json()["user"]["id"]), True)


def client_body(**updates):
    return {"name": "Campus", "client_type": "confidential", "trust_level": "external",
            "redirect_uris": ["https://campus.example/callback", "http://localhost:3000/callback"],
            "allowed_scopes": ["openid", "profile"], **updates}


def test_client_crud_hash_rotation_and_disable(flow, caplog):
    admin_login(flow)
    created = flow.client.post(BASE, json=client_body(), headers=ORIGIN)
    assert created.status_code == 201
    data = created.json()
    client_id, secret = data["client_id"], data["client_secret"]
    assert secret not in caplog.text
    with Session(flow.engine) as session:
        client = session.get(SSOClient, client_id)
        assert secret not in client.secret_hash
        assert verify_client_secret(client, secret)
        assert not verify_client_secret(client, "wrong")
        validate_client_request(session, client_id, data["redirect_uris"][0], ["openid"])
        for uri, scopes in [(data["redirect_uris"][0] + "/", ["openid"]), (data["redirect_uris"][0], ["email"])]:
            with pytest.raises(HTTPException):
                validate_client_request(session, client_id, uri, scopes)
    assert "client_secret" not in flow.client.get(BASE + "/" + client_id).json()
    assert "secret_hash" not in flow.client.get(BASE).text
    rotated = flow.client.post(BASE + "/" + client_id + "/rotate-secret", headers=ORIGIN)
    assert rotated.status_code == 200
    with Session(flow.engine) as session:
        client = session.get(SSOClient, client_id)
        assert not verify_client_secret(client, secret)
        assert verify_client_secret(client, rotated.json()["client_secret"])
    patched = flow.client.patch(BASE + "/" + client_id, json={"enabled": False, "trust_level": "first_party"}, headers=ORIGIN)
    assert patched.status_code == 200 and patched.json()["trust_level"] == "first_party"
    with Session(flow.engine) as session:
        with pytest.raises(HTTPException):
            validate_client_request(session, client_id, data["redirect_uris"][0], ["openid"])
        assert not verify_client_secret(session.get(SSOClient, client_id), rotated.json()["client_secret"])
    assert flow.client.delete(BASE + "/" + client_id, headers=ORIGIN).status_code == 204
    assert flow.client.get(BASE + "/" + client_id).status_code == 404


@pytest.mark.parametrize("client_type,trust", [("public", "external"), ("public", "first_party"), ("confidential", "external"), ("confidential", "first_party")])
def test_all_client_type_and_trust_combinations(flow, client_type, trust):
    admin_login(flow)
    response = flow.client.post(BASE, json=client_body(client_type=client_type, trust_level=trust), headers=ORIGIN)
    assert response.status_code == 201
    assert response.json()["trust_level"] == trust
    assert ("client_secret" in response.json()) == (client_type == "confidential")
    if client_type == "public":
        assert flow.client.post(BASE + "/" + response.json()["client_id"] + "/rotate-secret", headers=ORIGIN).status_code == 409


def test_client_management_requires_admin_and_origin(flow):
    assert flow.client.get(BASE).status_code == 401
    login(flow)
    assert flow.client.post(BASE, json=client_body(), headers=ORIGIN).status_code == 403
    with Session(flow.engine) as session:
        user_id = session.scalar(select(User)).id
    set_admin(flow.engine, user_id, True)
    assert flow.client.post(BASE, json=client_body()).status_code == 403
    assert flow.client.post(BASE, json=client_body(), headers={"Origin": "https://evil.example"}).status_code == 403


@pytest.mark.parametrize("updates", [
    {"redirect_uris": ["https://campus.example/callback#fragment"]},
    {"redirect_uris": ["https://*.example/callback"]},
    {"redirect_uris": ["http://remote.example/callback"]},
    {"redirect_uris": ["https://user:secret@campus.example/callback"]},
    {"redirect_uris": ["https://campus.example/callback?code=fixed"]},
    {"allowed_scopes": ["openid profile"]}, {"allowed_scopes": ["openid", "openid"]},
])
def test_invalid_registration_is_rejected(flow, updates):
    admin_login(flow)
    assert flow.client.post(BASE, json=client_body(**updates), headers=ORIGIN).status_code == 422


def test_clients_migration_and_metadata(database):
    engine, config = database
    command.upgrade(config, "head")
    command.check(config)
    command.downgrade(config, "20261015_0004")
    assert "sso_clients" not in inspect(engine).get_table_names()
    command.upgrade(config, "head")
    command.check(config)
