"""Redis is authoritative for one-time acceptance. All transitions run in one Lua call."""

import hashlib

from qr.dynamic_tokens import TOKEN_TYPE

PREFIX = "qr:dyn:state:"


class DynamicStoreUnavailable(RuntimeError):
    pass


def state_key(jti: str) -> str:
    return PREFIX + hashlib.sha256(jti.encode("ascii")).hexdigest()


# Use Redis TIME, including after queueing delays, rather than trusting a client-supplied clock.
# Keep terminal states through exp; deleting them must never make registration possible again.
REGISTER = """
local now = tonumber(redis.call('TIME')[1])
local exp = tonumber(ARGV[1])
if exp <= now or redis.call('EXISTS', KEYS[1]) == 1 then return 0 end
redis.call('HSET', KEYS[1], 'state', 'ISSUED', 'exp', ARGV[1], 'typ', ARGV[2], 'v', ARGV[3])
redis.call('EXPIREAT', KEYS[1], exp)
return 1
"""

TRANSITION = """
local values = redis.call('HMGET', KEYS[1], 'state', 'exp', 'typ', 'v')
if not values[1] then return 0 end
local exp = tonumber(values[2])
if not exp or values[2] ~= ARGV[1] or values[3] ~= ARGV[2] or values[4] ~= ARGV[3] then return 0 end
if exp <= tonumber(redis.call('TIME')[1]) then
    if values[1] == 'ISSUED' then redis.call('HSET', KEYS[1], 'state', 'EXPIRED') end
    return 0
end
if values[1] ~= 'ISSUED' then return 0 end
redis.call('HSET', KEYS[1], 'state', ARGV[4])
return 1
"""


async def _execute(client, script, claims, *args) -> bool:
    try:
        result = await client.eval(script, 1, state_key(claims["jti"]), claims["exp"], TOKEN_TYPE, 1, *args)
        if type(result) is not int or result not in (0, 1):
            raise ValueError()
        return result == 1
    except Exception:
        # A timeout can follow a committed transition. Never retry acceptance or expose Redis details.
        raise DynamicStoreUnavailable("Dynamic QR state store unavailable") from None


async def register(client, claims) -> None:
    if not await _execute(client, REGISTER, claims):
        raise DynamicStoreUnavailable("Dynamic QR registration could not be confirmed")


async def consume(client, claims) -> bool:
    return await _execute(client, TRANSITION, claims, "CONSUMED")


async def revoke(client, claims) -> bool:
    return await _execute(client, TRANSITION, claims, "REVOKED")
