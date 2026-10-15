import asyncio
import base64
import os
import time
import uuid
from unittest.mock import AsyncMock

import pytest
from redis.asyncio import Redis
from redis.exceptions import ConnectionError, TimeoutError

from qr.nonces import (
    DEFAULT_NONCE_TTL, MAX_NONCE_LENGTH, MAX_TTL, NONCE_NAMESPACE,
    NonceReplayError, NonceSettings, NonceStoreUnavailable, NonceValidationError,
    consume_nonce, generate_nonce,
)


def test_generation_format_entropy_and_length():
    values = {generate_nonce(now=1234567890) for _ in range(1000)}
    assert len(values) == 1000
    for value in values:
        version, timestamp, encoded = value.split(".")
        assert (version, timestamp) == ("v1", "1234567890")
        assert len(base64.urlsafe_b64decode(encoded + "=")) == 32
    assert len(generate_nonce(now=99999999999999999)) == MAX_NONCE_LENGTH


@pytest.mark.parametrize("now", [-1, True, 1.5, "123", 10**17])
def test_generation_rejects_invalid_time(now):
    with pytest.raises(NonceValidationError):
        generate_nonce(now=now)


@pytest.mark.parametrize("ttl", [0, -1, 601, True, 1.5, "300"])
def test_invalid_ttl(ttl):
    with pytest.raises(ValueError):
        NonceSettings(ttl)


def test_environment_settings(monkeypatch):
    monkeypatch.delenv("QR_NONCE_TTL_SECONDS", raising=False)
    assert NonceSettings.from_environment().ttl == DEFAULT_NONCE_TTL
    monkeypatch.setenv("QR_NONCE_TTL_SECONDS", str(MAX_TTL))
    assert NonceSettings.from_environment().ttl == MAX_TTL
    monkeypatch.setenv("QR_NONCE_TTL_SECONDS", "private-invalid-setting")
    with pytest.raises(ValueError) as error:
        NonceSettings.from_environment()
    assert "private-invalid-setting" not in str(error.value)


def test_atomic_command_uses_remaining_ttl_and_digests(monkeypatch):
    monkeypatch.setattr("qr.nonces.time.time", lambda: 1000)
    nonce = generate_nonce(now=975)
    client = AsyncMock()
    client.set.return_value = True
    asyncio.run(consume_nonce(client, client_id="trusted-client", nonce=nonce))
    args, kwargs = client.set.call_args
    assert args[1] == "1"
    assert kwargs == {"nx": True, "ex": 275}
    assert args[0].startswith(NONCE_NAMESPACE + ":")
    assert "trusted-client" not in args[0] and nonce not in args[0]


@pytest.mark.parametrize("age,accepted", [(0, True), (299, True), (300, False), (301, False), (-1, False)])
def test_freshness_boundaries(monkeypatch, age, accepted):
    monkeypatch.setattr("qr.nonces.time.time", lambda: 1000)
    client = AsyncMock()
    client.set.return_value = True
    nonce = generate_nonce(now=1000 - age)
    if accepted:
        asyncio.run(consume_nonce(client, client_id="client", nonce=nonce))
        assert client.set.call_args.kwargs["ex"] == 300 - age
    else:
        with pytest.raises(NonceValidationError):
            asyncio.run(consume_nonce(client, client_id="client", nonce=nonce))
        client.set.assert_not_called()


@pytest.mark.parametrize("nonce", [None, b"v1.123.a", "", "x" * 65, "v2.123." + "A" * 43,
                                  "v1.0123." + "A" * 43, "v1.-1." + "A" * 43,
                                  "v1.123." + "A" * 42, "v1.123." + "A" * 42 + "B",
                                  "v1.123." + "A" * 43 + "=", "v1.123." + "é" * 43])
def test_malformed_nonce_rejected_without_redis(nonce):
    client = AsyncMock()
    with pytest.raises(NonceValidationError):
        asyncio.run(consume_nonce(client, client_id="client", nonce=nonce))
    client.set.assert_not_called()


@pytest.mark.parametrize("reply,error", [(None, NonceReplayError), (False, NonceStoreUnavailable),
                                         ("OK", NonceStoreUnavailable), (1, NonceStoreUnavailable),
                                         (b"OK", NonceStoreUnavailable)])
def test_replay_and_ambiguous_reply_fail_closed(reply, error):
    client = AsyncMock()
    client.set.return_value = reply
    with pytest.raises(error):
        asyncio.run(consume_nonce(client, client_id="client", nonce=generate_nonce()))


@pytest.mark.parametrize("error", [ConnectionError, TimeoutError, OSError, RuntimeError])
def test_store_failure_is_sanitized(error):
    client = AsyncMock()
    client.set.side_effect = error("redis://private-user:secret@host credential-token")
    with pytest.raises(NonceStoreUnavailable) as caught:
        asyncio.run(consume_nonce(client, client_id="client", nonce=generate_nonce()))
    assert str(caught.value) == "Nonce store unavailable"
    assert caught.value.__suppress_context__


@pytest.mark.parametrize("client_id,namespace", [(None, NONCE_NAMESPACE), ("", NONCE_NAMESPACE),
                                                (" client", NONCE_NAMESPACE), ("x" * 257, NONCE_NAMESPACE),
                                                ("client", "bad scope"), ("client", None)])
def test_invalid_scope(client_id, namespace):
    client = AsyncMock()
    with pytest.raises(NonceValidationError):
        asyncio.run(consume_nonce(client, client_id=client_id, namespace=namespace, nonce=generate_nonce()))
    client.set.assert_not_called()


def test_real_redis_atomic_concurrency_scope_ttl_and_expiry(monkeypatch):
    url = os.getenv("TEST_QR_NONCE_REDIS_URL")
    if not url:
        pytest.skip("Set TEST_QR_NONCE_REDIS_URL to a dedicated Redis instance")
    namespace = "qr-nonce-test:" + uuid.uuid4().hex

    async def check():
        client = Redis.from_url(url, decode_responses=True, socket_timeout=2)
        now = int(time.time())
        monkeypatch.setattr("qr.nonces.time.time", lambda: now)
        nonce = generate_nonce(now=now)
        try:
            outcomes = await asyncio.gather(*[
                consume_nonce(client, client_id="client-a", nonce=nonce, namespace=namespace)
                for _ in range(100)
            ], return_exceptions=True)
            assert sum(result is None for result in outcomes) == 1
            assert sum(isinstance(result, NonceReplayError) for result in outcomes) == 99
            await consume_nonce(client, client_id="client-b", nonce=nonce, namespace=namespace)
            keys = await client.keys(namespace + ":*")
            assert len(keys) == 2
            assert all(0 < ttl <= DEFAULT_NONCE_TTL for ttl in [await client.ttl(key) for key in keys])
            # No QR identifier participates in the key: the same request nonce
            # stays consumed even if its caller switches to another QR token.
            with pytest.raises(NonceReplayError):
                await consume_nonce(client, client_id="client-a", nonce=nonce, namespace=namespace)
            # Remove state to simulate expiry, then advance the verifier clock:
            # the timestamp prevents reusing an expired nonce without Redis state.
            await client.delete(*keys)
            monkeypatch.setattr("qr.nonces.time.time", lambda: now + DEFAULT_NONCE_TTL)
            with pytest.raises(NonceValidationError):
                await consume_nonce(client, client_id="client-a", nonce=nonce, namespace=namespace)
            assert await client.keys(namespace + ":*") == []
            # A short TTL also expires on Redis itself.
            monkeypatch.setattr("qr.nonces.time.time", lambda: now)
            await consume_nonce(client, client_id="client-a", nonce=generate_nonce(now=now),
                                namespace=namespace, settings=NonceSettings(ttl=1))
            await asyncio.sleep(1.1)
            assert await client.keys(namespace + ":*") == []
        finally:
            keys = await client.keys(namespace + ":*")
            if keys:
                await client.delete(*keys)
            await client.aclose()

    asyncio.run(check())
