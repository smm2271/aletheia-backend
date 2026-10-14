import asyncio
import os
import secrets
from urllib.parse import urlsplit

from redis.asyncio import Redis
from redis.asyncio.retry import Retry
from redis.backoff import NoBackoff
from redis.exceptions import RedisError


def create_redis_client() -> Redis:
    url = os.getenv("REDIS_URL", "").strip()
    if not url:
        raise RuntimeError("Set REDIS_URL to configure Redis")
    try:
        parsed = urlsplit(url)
        if parsed.scheme not in {"redis", "rediss"} or not parsed.hostname:
            raise ValueError()
        if parsed.path not in {"", "/"} and int(parsed.path.removeprefix("/")) < 0:
            raise ValueError()
        return Redis.from_url(
            url, decode_responses=True, socket_connect_timeout=3,
            socket_timeout=3, retry=Retry(NoBackoff(), 0),
        )
    except ValueError:
        raise RuntimeError("Invalid REDIS_URL configuration") from None


async def verify_read_write(client: Redis) -> None:
    """Check an isolated expiring key, without modifying application state."""
    key = "aletheia:redis-check:" + secrets.token_hex(16)
    value = secrets.token_hex(16)
    try:
        await client.set(key, value, ex=60)
        if await client.get(key) != value or not 0 < await client.ttl(key) <= 60:
            raise RuntimeError("Redis read/write or TTL verification failed")
    finally:
        await client.delete(key)


async def main() -> None:
    client = create_redis_client()
    try:
        await client.ping()
        await verify_read_write(client)
        print("Redis ping, read/write and TTL checks passed")
    finally:
        await client.aclose()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (RedisError, RuntimeError):
        raise SystemExit("Redis connectivity check failed; verify configuration and service availability") from None
