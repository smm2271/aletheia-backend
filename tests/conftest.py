import os

import pytest
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text


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
