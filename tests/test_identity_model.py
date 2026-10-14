import os
import uuid

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, select, text
from sqlalchemy.exc import IntegrityError, ProgrammingError
from sqlalchemy.orm import Session

from models import Affiliation, ExternalIdentity, User


@pytest.fixture
def database(monkeypatch):
    url = os.getenv("TEST_DATABASE_URL")
    if not url:
        pytest.skip("Set TEST_DATABASE_URL to a dedicated empty PostgreSQL database")
    monkeypatch.setenv("DATABASE_URL", url)
    engine = create_engine(url)
    assert not inspect(engine).get_table_names(), "Tests require an empty database"
    config = Config("alembic.ini")
    try:
        yield engine, config
    finally:
        with engine.begin() as connection:
            connection.execute(text("DROP SCHEMA public CASCADE"))
            connection.execute(text("CREATE SCHEMA public"))
        engine.dispose()


def make_user(email="student@example.edu"):
    return User(email=email, affiliation=Affiliation.STUDENT)


def test_fresh_schema_relationships_and_identity_constraints(database):
    engine, config = database
    command.upgrade(config, "head")
    command.check(config)
    assert "google_sub" not in {c["name"] for c in inspect(engine).get_columns("users")}
    with Session(engine) as session:
        user = make_user()
        user.external_identities = [
            ExternalIdentity(provider="google", subject="subject-1"),
            ExternalIdentity(provider="other-issuer", subject="subject-1"),
            ExternalIdentity(provider="google", subject="subject-2"),
        ]
        session.add(user)
        session.commit()
        user_id = user.id
        session.expire_all()
        assert len(user.external_identities) == 3
        assert all(identity.user is user for identity in user.external_identities)
        user.email = "changed@example.edu"
        session.commit()
        assert session.scalar(select(ExternalIdentity).where(
            ExternalIdentity.provider == "google", ExternalIdentity.subject == "subject-1"
        )).user_id == user_id
        session.add(ExternalIdentity(user_id=user_id, provider="google", subject="subject-1"))
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()
        session.add(ExternalIdentity(user_id=uuid.uuid4(), provider="google", subject="orphan"))
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()
        session.add(make_user("changed@example.edu"))
        with pytest.raises(IntegrityError):
            session.commit()
        session.rollback()
        user.external_identities.pop()
        session.commit()
        assert len(session.scalars(select(ExternalIdentity)).all()) == 2
    # Exercise database cascading with no ORM relationship loaded.
    with engine.begin() as connection:
        connection.execute(text("DELETE FROM users WHERE id = :id"), {"id": user_id})
        assert connection.scalar(text("SELECT count(*) FROM external_identities")) == 0
    command.downgrade(config, "base")


def test_existing_google_identity_survives_upgrade_and_downgrade(database):
    engine, config = database
    command.upgrade(config, "20260911_0001")
    user_id = uuid.uuid4()
    with engine.begin() as connection:
        connection.execute(text("""
            INSERT INTO users (id, google_sub, email, affiliation)
            VALUES (:id, 'original-sub', 'original@example.edu', 'teacher')
        """), {"id": user_id})
    command.upgrade(config, "head")
    with Session(engine) as session:
        user = session.get(User, user_id)
        assert user.email == "original@example.edu"
        assert user.affiliation == Affiliation.TEACHER
        assert [(e.provider, e.subject) for e in user.external_identities] == [("google", "original-sub")]
    command.downgrade(config, "20260911_0001")
    with engine.connect() as connection:
        assert connection.scalar(text("SELECT google_sub FROM users WHERE id = :id"), {"id": user_id}) == "original-sub"
    command.upgrade(config, "head")
    command.check(config)


@pytest.mark.parametrize("identities", [[], [("other-issuer", "s")], [("google", "s1"), ("google", "s2")]])
def test_downgrade_refuses_lossy_identity_conversion(database, identities):
    engine, config = database
    command.upgrade(config, "head")
    with Session(engine) as session:
        user = make_user()
        user.external_identities = [ExternalIdentity(provider=p, subject=s) for p, s in identities]
        session.add(user)
        session.commit()
    with pytest.raises(ProgrammingError, match="Cannot downgrade"):
        command.downgrade(config, "20260911_0001")
    with engine.connect() as connection:
        assert connection.scalar(text("SELECT version_num FROM alembic_version")) == "20261014_0002"
        assert connection.scalar(text("SELECT count(*) FROM external_identities")) == len(identities)
    assert "google_sub" not in {c["name"] for c in inspect(engine).get_columns("users")}
