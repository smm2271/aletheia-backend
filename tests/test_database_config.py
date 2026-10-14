from sqlalchemy.engine import make_url

import pytest

from database import get_database_url


@pytest.fixture(autouse=True)
def clean_database_environment(monkeypatch):
    for key in ("DATABASE_URL", "POSTGRES_USER", "POSTGRES_PASSWORD", "POSTGRES_DB", "POSTGRES_HOST", "POSTGRES_PORT"):
        monkeypatch.delenv(key, raising=False)


def test_explicit_url_takes_precedence(monkeypatch):
    url = "postgresql+psycopg://test:password@localhost:5433/test"
    monkeypatch.setenv("DATABASE_URL", url)
    assert get_database_url() == url


def test_shared_settings_preserve_special_characters(monkeypatch):
    for key, value in {
        "DATABASE_URL": "", "POSTGRES_USER": "user", "POSTGRES_PASSWORD": "p@ss:%/word",
        "POSTGRES_HOST": "db", "POSTGRES_DB": "test", "POSTGRES_PORT": "5433",
    }.items():
        monkeypatch.setenv(key, value)
    url = make_url(get_database_url())
    assert url.password == "p@ss:%/word"
    assert url.host == "db"
    assert url.port == 5433
    assert url.database == "test"


def test_missing_settings_fail_without_secret_defaults():
    with pytest.raises(RuntimeError, match="Set DATABASE_URL"):
        get_database_url()
