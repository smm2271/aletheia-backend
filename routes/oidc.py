from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from signing_keys import KeyManagementError

router = APIRouter(tags=["OpenID Connect"])


def configured_issuer(request):
    issuer = getattr(request.app.state, "token_issuer", None)
    if issuer is None:
        raise HTTPException(503, "SSO is not configured", headers={"Cache-Control": "no-store"})
    return issuer


@router.get("/.well-known/jwks.json")
async def jwks(request: Request):
    issuer = configured_issuer(request)
    try:
        document = await run_in_threadpool(issuer.keys.jwks)
    except (KeyManagementError, AttributeError):
        raise HTTPException(503, "SSO keys unavailable", headers={"Cache-Control": "no-store"}) from None
    return JSONResponse(document, headers={"Cache-Control": "no-store"})


@router.get("/.well-known/openid-configuration")
async def discovery(request: Request):
    issuer = configured_issuer(request).settings.issuer
    base = issuer.rstrip("/")
    return JSONResponse({
        "issuer": issuer,
        "authorization_endpoint": base + "/authorize",
        "token_endpoint": base + "/token",
        "jwks_uri": base + "/.well-known/jwks.json",
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code"],
        "subject_types_supported": ["public"],
        "scopes_supported": ["openid", "profile", "email", "student:eligibility:read"],
        "id_token_signing_alg_values_supported": ["EdDSA"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
        "code_challenge_methods_supported": ["S256"],
        "claims_supported": ["iss", "sub", "aud", "iat", "exp", "nonce"],
    }, headers={"Cache-Control": "no-store"})
