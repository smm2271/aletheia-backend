import uuid
from datetime import datetime, timezone

import pytest
from alembic import command
from sqlalchemy import inspect, select, text
from sqlalchemy.orm import Session

from admin.bootstrap import set_admin
from models import User
from test_browser_session import login
from test_google_oauth import flow, signing_key


def test_admin_boundary_and_immediate_revocation(flow):
    assert flow.client.get("/api/v1/admin/me").status_code == 401
    response, _ = login(flow)
    user_id = uuid.UUID(response.json()["user"]["id"])
    assert flow.client.get("/api/v1/admin/me").status_code == 403
    set_admin(flow.engine, user_id, True)
    assert flow.client.get("/api/v1/admin/me").json() == {"user_id": str(user_id), "is_admin": True}
    set_admin(flow.engine, user_id, False)
    assert flow.client.get("/api/v1/admin/me").status_code == 403


def test_bootstrap_requires_existing_active_user(flow):
    with pytest.raises(ValueError, match="not found"):
        set_admin(flow.engine, uuid.uuid4(), True)
    response, _ = login(flow)
    user_id = uuid.UUID(response.json()["user"]["id"])
    with Session(flow.engine) as session:
        user = session.scalar(select(User))
        assert user.is_admin is False
        user.disabled_at = datetime.now(timezone.utc)
        session.commit()
    with pytest.raises(ValueError, match="disabled"):
        set_admin(flow.engine, user_id, True)
    assert flow.client.get("/api/v1/admin/me").status_code == 401


def test_admin_migration_existing_users_default_normal(database):
    engine, config = database
    command.upgrade(config, "20261014_0003")
    with engine.begin() as connection:
        connection.execute(text("INSERT INTO users(email, affiliation) VALUES ('existing@example.edu', 'teacher')"))
    command.upgrade(config, "head")
    with engine.connect() as connection:
        assert connection.scalar(text("SELECT is_admin FROM users")) is False
    command.check(config)
    command.downgrade(config, "20261014_0003")
    assert "is_admin" not in {c["name"] for c in inspect(engine).get_columns("users")}
