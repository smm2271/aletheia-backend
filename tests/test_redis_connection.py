import asyncio
import os
import uuid

import pytest
from fastapi.testclient import TestClient
from redis.exceptions import ConnectionError

from main import app
from redis_connection import create_redis_client, verify_read_write


def test_missing_url_has_no_implicit_connection(monkeypatch):
    monkeypatch.delenv("REDIS_URL", raising=False)
    with pytest.raises(RuntimeError, match="Set REDIS_URL"):
        create_redis_client()


@pytest.mark.parametrize("url", ["http://user:private-password@localhost", "redis://localhost/not-a-db", "redis://[invalid"])
def test_invalid_url_errors_do_not_include_credentials(monkeypatch, url):
    monkeypatch.setenv("REDIS_URL", url)
    with pytest.raises(RuntimeError, match="Invalid REDIS_URL") as error:
        create_redis_client()
    assert "private-password" not in str(error.value)


@pytest.fixture
def redis_url(monkeypatch):
    url = os.getenv("TEST_REDIS_URL")
    if not url:
        pytest.skip("Set TEST_REDIS_URL to a dedicated Redis database")
    monkeypatch.setenv("REDIS_URL", url)
    return url


def test_real_redis_read_write_ttl_and_cleanup(redis_url, monkeypatch):
    suffix = uuid.uuid4().hex
    monkeypatch.setattr("redis_connection.secrets.token_hex", lambda _: suffix)
    async def check():
        client = create_redis_client()
        key = "aletheia:redis-check:" + suffix
        expiring_key = "aletheia:ttl-test:" + suffix
        try:
            assert await client.ping()
            await verify_read_write(client)
            assert await client.get(key) is None
            await client.set(expiring_key, "temporary", px=100)
            assert await client.get(expiring_key) == "temporary"
            await asyncio.sleep(0.15)
            assert await client.get(expiring_key) is None
        finally:
            await client.delete(key, expiring_key)
            await client.aclose()
    asyncio.run(check())


def test_redis_readiness_and_outage_response(database, redis_url, monkeypatch):
    with TestClient(app) as client:
        assert client.get("/health/redis").status_code == 200
        assert client.get("/health").status_code == 200
        async def unavailable():
            raise ConnectionError("private connection details")
        monkeypatch.setattr(app.state.redis_client, "ping", unavailable)
        response = client.get("/health/redis")
        assert response.status_code == 503
        assert response.json() == {"detail": "Redis unavailable"}
        assert client.get("/health").status_code == 200
