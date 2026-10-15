"""Week-six chain: controlled Google -> Session -> OIDC client -> eligibility."""
import time
import uuid
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlsplit

from sqlalchemy.orm import Session

from models import EligibilityStatus, SSOClient, StudentEligibility, VerificationStatus
from student.eligibility import SCOPE
from test_oidc_integration import oidc_flow
from test_authorization import auth_flow
from test_google_oauth import flow, signing_key


def test_google_to_client_to_eligibility_uses_one_authorization_grant(oidc_flow):
    server, client, demo, routing, *_ = oidc_flow
    demo.state.settings = replace(demo.state.settings, scopes=("openid", SCOPE))
    with Session(server.engine) as session:
        session.get(SSOClient, "consumer").allowed_scopes = ["openid", SCOPE]
        session.commit()
    captured = {}
    original_post = routing.post

    async def exchange(url, **kwargs):
        response = await original_post(url, **kwargs)
        captured.update(response.json())
        return response
    routing.post = exchange

    started = client.get("/login", follow_redirects=False)
    authorize = server.client.get(started.headers["location"], follow_redirects=False)
    assert authorize.status_code == 302
    google = server.client.get(authorize.headers["location"], follow_redirects=False)
    query = parse_qs(urlsplit(google.headers["location"]).query)
    now = int(time.time())
    server.provider.claims = {
        "iss": "https://accounts.google.com", "aud": "test-client", "iat": now, "exp": now + 300,
        "sub": "week-six-user", "nonce": query["nonce"][0], "email": "s1234567@school.edu",
        "email_verified": True,
    }
    callback = server.client.get("/auth/google/callback", params={"state": query["state"][0], "code": "controlled-google-code"}, follow_redirects=False)
    assert callback.status_code == 303
    granted = server.client.get(callback.headers["location"], follow_redirects=False)
    assert granted.status_code == 302
    assert client.get(granted.headers["location"], follow_redirects=False).status_code == 302
    identity = client.get("/me").json()
    assert identity["authenticated"]
    subject = uuid.UUID(identity["sub"])
    assert server.client.get("/auth/me").json()["user"]["id"] == str(subject)
    assert len(server.provider.posts) == 1
    assert captured["scope"] == "openid " + SCOPE
    # The same token exchange validated by the client also supplies its API access token.
    headers = {"Authorization": "Bearer " + captured["access_token"]}
    unknown = server.client.get("/api/v1/student/eligibility", headers=headers)
    assert unknown.status_code == 200 and unknown.json()["status"] == "unknown"
    with Session(server.engine) as session:
        updated = datetime.now(timezone.utc)
        session.add(StudentEligibility(user_id=subject, status=EligibilityStatus.ELIGIBLE,
                                       source="test_fixture", verification_status=VerificationStatus.TEST,
                                       updated_at=updated, valid_until=updated + timedelta(hours=1)))
        session.commit()
    eligible = server.client.get("/api/v1/student/eligibility", headers=headers)
    assert eligible.json()["status"] == "eligible" and eligible.json()["verified"] is False
    # Client and issuer sessions remain separate on client logout.
    assert client.post("/logout", headers={"Origin": demo.state.settings.origin}).status_code == 204
    assert client.get("/me").status_code == 401
    assert server.client.get("/auth/me").status_code == 200
