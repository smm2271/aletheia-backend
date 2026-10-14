from urllib.parse import parse_qsl

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from sso.token import (
    OAuthError,
    OAuthErrorResponse,
    TokenRequest,
    TokenResponse,
    authenticate_client,
    consume_token_code,
    verify_token_user,
)

router = APIRouter(tags=["Argus SSO"])


def oauth_error_response(
    error: str,
    description: str | None = None,
    status_code: int = 400,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    content = {"error": error}
    if description:
        content["error_description"] = description
    resp_headers = {
        "Cache-Control": "no-store",
        "Pragma": "no-cache",
        "Referrer-Policy": "no-referrer",
    }
    if headers:
        resp_headers.update(headers)
    return JSONResponse(content=content, status_code=status_code, headers=resp_headers)


@router.post(
    "/token",
    response_model=TokenResponse,
    responses={
        400: {"model": OAuthErrorResponse, "description": "Bad Request (OAuth 2.0 Error: invalid_request, invalid_grant, unsupported_grant_type)"},
        401: {"model": OAuthErrorResponse, "description": "Unauthorized (Client authentication failed)"},
        503: {"model": OAuthErrorResponse, "description": "Service Unavailable (Token issuance not configured or store unavailable)"},
    },
    summary="Exchange authorization code for tokens",
    description="OAuth 2.0 Token Endpoint for Argus SSO. Accepts application/x-www-form-urlencoded.",
)
async def exchange_token(request: Request):
    content_type = request.headers.get("content-type", "")
    if not content_type.startswith("application/x-www-form-urlencoded"):
        return oauth_error_response("invalid_request", "Content-Type must be application/x-www-form-urlencoded", 400)

    body_bytes = await request.body()
    if len(body_bytes) > 16384:
        return oauth_error_response("invalid_request", "Request body exceeds allowed size", 400)

    try:
        body_str = body_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return oauth_error_response("invalid_request", "Invalid character encoding; UTF-8 is required", 400)

    pairs = parse_qsl(body_str, keep_blank_values=True)
    seen_keys = set()
    form_data: dict[str, str] = {}
    for k, v in pairs:
        if k in seen_keys:
            return oauth_error_response("invalid_request", f"Duplicate parameter: {k}", 400)
        seen_keys.add(k)
        form_data[k] = v

    grant_type = form_data.get("grant_type")
    if not grant_type:
        return oauth_error_response("invalid_request", "Missing grant_type parameter", 400)
    if grant_type != "authorization_code":
        return oauth_error_response("unsupported_grant_type", "Grant type must be authorization_code", 400)

    try:
        token_req = TokenRequest.model_validate(form_data)
    except ValidationError:
        return oauth_error_response("invalid_request", "Invalid request parameters", 400)

    auth_header = request.headers.get("authorization")

    try:
        with Session(request.app.state.database_engine) as session:
            client = await run_in_threadpool(
                authenticate_client,
                session,
                auth_header,
                token_req.client_id,
                token_req.client_secret,
            )

            record = await consume_token_code(
                request.app.state.redis_client,
                token_req.code,
                client.client_id,
                token_req.redirect_uri,
                token_req.code_verifier,
            )

            user = await run_in_threadpool(verify_token_user, session, record["user_id"])

        issuer = getattr(request.app.state, "token_issuer", None)
        if issuer is None:
            return oauth_error_response(
                "temporarily_unavailable",
                "Token issuance service is not configured",
                503,
            )

        try:
            token_response = await issuer.issue(user, client, record["scope"], record.get("nonce"))
        except Exception:
            return oauth_error_response(
                "temporarily_unavailable",
                "Token issuance failed",
                503,
            )

        return JSONResponse(
            content=token_response.model_dump(exclude_none=True),
            status_code=200,
            headers={
                "Cache-Control": "no-store",
                "Pragma": "no-cache",
                "Referrer-Policy": "no-referrer",
            },
        )

    except OAuthError as err:
        return oauth_error_response(
            err.error,
            err.error_description,
            status_code=err.status_code,
            headers=err.headers,
        )
