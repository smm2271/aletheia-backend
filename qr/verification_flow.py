"""Authorize and validate first; atomically reserve the transaction nonce last."""
from fastapi import HTTPException, Request

from qr.nonces import NonceReplayError, NonceStoreUnavailable, NonceValidationError, consume_nonce
from qr.verification import verify_for_client


async def verify_with_nonce(request: Request, token: str, nonce: str) -> None:
    client_id = await verify_for_client(request, token)
    settings = getattr(request.app.state, "qr_nonce_settings", None)
    if settings is None:
        raise HTTPException(503, "QR verification is not configured", headers={"Cache-Control": "no-store"})
    try:
        await consume_nonce(request.app.state.redis_client, client_id=client_id, nonce=nonce, settings=settings)
    except NonceReplayError:
        raise HTTPException(409, "Verification request already consumed", headers={"Cache-Control": "no-store"}) from None
    except NonceValidationError:
        raise HTTPException(400, "Invalid or expired verification nonce", headers={"Cache-Control": "no-store"}) from None
    except NonceStoreUnavailable:
        raise HTTPException(503, "Verification request store unavailable", headers={"Cache-Control": "no-store"}) from None
