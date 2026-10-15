import uuid
from datetime import datetime, timezone

from fastapi import HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from models import EligibilityStatus, SSOClient, StudentEligibility, User, VerificationStatus
from signing_keys import KeyManagementError
from sso.jwt import JWTValidationError, JWTValidator

SCOPE = "student:eligibility:read"


class EligibilityResponse(BaseModel):
    status: EligibilityStatus
    source: str | None = None
    verified: bool = False
    verification_status: VerificationStatus | None = None
    updated_at: datetime | None = None
    valid_until: datetime | None = None


def decide(evidence: StudentEligibility | None, now: datetime | None = None) -> EligibilityResponse:
    if evidence is None:
        return EligibilityResponse(status=EligibilityStatus.UNKNOWN)
    now = now or datetime.now(timezone.utc)
    current = evidence.updated_at <= now and evidence.valid_until is not None and now < evidence.valid_until
    trusted = evidence.verification_status == VerificationStatus.VERIFIED and evidence.source != "test_fixture"
    test = evidence.source == "test_fixture" and evidence.verification_status == VerificationStatus.TEST
    return EligibilityResponse(
        status=evidence.status if current and (trusted or test) else EligibilityStatus.UNKNOWN,
        source=evidence.source, verified=bool(current and trusted), verification_status=evidence.verification_status,
        updated_at=evidence.updated_at, valid_until=evidence.valid_until,
    )


def load_eligibility(engine, claims):
    with Session(engine) as session:
        user = session.get(User, uuid.UUID(claims["sub"]))
        client = session.get(SSOClient, claims["client_id"])
        if user is None or user.disabled_at is not None or client is None or not client.enabled:
            raise HTTPException(401, "Invalid access token", headers={"WWW-Authenticate": 'Bearer error="invalid_token"'})
        if SCOPE not in client.allowed_scopes:
            raise HTTPException(403, "Client is not authorized", headers={"WWW-Authenticate": f'Bearer error="insufficient_scope", scope="{SCOPE}"'})
        return decide(session.get(StudentEligibility, user.id))


async def current_eligibility(request: Request) -> EligibilityResponse:
    authorization = request.headers.get("authorization", "").split()
    if len(authorization) != 2 or authorization[0].lower() != "bearer":
        raise HTTPException(401, "Bearer access token required", headers={"WWW-Authenticate": "Bearer"})
    issuer = getattr(request.app.state, "token_issuer", None)
    if issuer is None:
        raise HTTPException(503, "SSO is not configured")
    try:
        validator = JWTValidator(issuer.settings, issuer.keys)
        claims = await run_in_threadpool(validator.validate_access_token, authorization[1], audience=issuer.settings.access_audience)
    except KeyManagementError:
        raise HTTPException(503, "SSO keys unavailable") from None
    except JWTValidationError:
        raise HTTPException(401, "Invalid access token", headers={"WWW-Authenticate": 'Bearer error="invalid_token"'}) from None
    if SCOPE not in claims["scope"].split(" "):
        raise HTTPException(403, "Required scope missing", headers={"WWW-Authenticate": f'Bearer error="insufficient_scope", scope="{SCOPE}"'})
    return await run_in_threadpool(load_eligibility, request.app.state.database_engine, claims)
