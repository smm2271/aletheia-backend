"""Live HTTP smoke test using isolated TEST_DATABASE_URL / TEST_REDIS_URL services.

Run after pytest against a dedicated database. Google is not contacted: the test
provisions one authenticated browser session through the backend session service.
"""
import asyncio
import base64
import hashlib
from io import BytesIO
import os
import secrets
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import httpx
import zxingcpp
from PIL import Image
from alembic import command
from alembic.config import Config
from sqlalchemy import inspect, text
from sqlalchemy.orm import Session

from auth.session import COOKIE_NAME, SessionSettings, create_session, revoke_session
from database import create_database_engine
from models import Affiliation, ClientType, EligibilityStatus, SSOClient, StudentEligibility, TrustLevel, User, VerificationStatus
from redis_connection import create_redis_client
from signing_keys import KeyRing, SigningKey, save_key_file
from signing_keys import FileKeyProvider
from sso.clients import hash_secret
from qr.encoding import encode_png
from qr.tokens import QRSettings, QRValidator


async def browser_session(user_id, token=None):
    client = create_redis_client()
    try:
        if token:
            await revoke_session(client, token)
        else:
            return await create_session(client, user_id, SessionSettings.from_environment())
    finally:
        await client.aclose()


def wait_for(url, processes):
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        if any(p.poll() is not None for p in processes):
            raise RuntimeError("Smoke server exited")
        try:
            if httpx.get(url, timeout=1).status_code == 200:
                return
        except httpx.HTTPError:
            pass
        time.sleep(0.1)
    raise RuntimeError("Smoke server did not become ready")


def main():
    issuer, origin = "http://localhost:18000", "http://127.0.0.1:18001"
    os.environ.update({
        "DATABASE_URL": os.environ["TEST_DATABASE_URL"], "REDIS_URL": os.environ["TEST_REDIS_URL"],
        "SESSION_PUBLIC_ORIGIN": issuer, "SESSION_COOKIE_SECURE": "false",
        "SSO_ISSUER": issuer, "SSO_ACCESS_AUDIENCE": "argus-api",
        "DEMO_ISSUER": issuer, "DEMO_PUBLIC_ORIGIN": origin,
        "DEMO_REDIS_URL": os.environ["TEST_REDIS_URL"],
    })
    engine, processes, token, user_id = create_database_engine(), [], None, None
    assert not inspect(engine).get_table_names(), "Smoke test requires a dedicated empty PostgreSQL database"
    client_id, secret = "smoke-" + secrets.token_hex(8), secrets.token_urlsafe(32)
    os.environ.update({"DEMO_CLIENT_ID": client_id, "DEMO_CLIENT_SECRET": secret})
    try:
        command.upgrade(Config("alembic.ini"), "head")
        with Session(engine) as session:
            user = User(email=client_id + "@example.edu", affiliation=Affiliation.STUDENT)
            session.add(user)
            session.flush()
            user_id = user.id
            session.add(SSOClient(client_id=client_id, name="Smoke", client_type=ClientType.CONFIDENTIAL,
                                  trust_level=TrustLevel.FIRST_PARTY, enabled=True, secret_hash=hash_secret(secret),
                                  redirect_uris=[origin + "/callback"], allowed_scopes=["openid", "student:eligibility:read"]))
            now = datetime.now(timezone.utc)
            session.add(StudentEligibility(user_id=user_id, status=EligibilityStatus.ELIGIBLE, source="test_fixture",
                                           verification_status=VerificationStatus.TEST, updated_at=now,
                                           valid_until=now + timedelta(hours=1)))
            session.commit()
        token = asyncio.run(browser_session(user_id))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "keys.json"
            save_key_file(path, KeyRing([SigningKey.generate("sso"), SigningKey.generate("qr")]), create=True)
            os.environ["SIGNING_KEYS_FILE"] = str(path)
            for module, port in (("main:app", "18000"), ("demo_client.app:app", "18001")):
                processes.append(subprocess.Popen([
                    sys.executable, "-m", "uvicorn", module, "--host", "127.0.0.1", "--port", port,
                    "--no-access-log", "--log-level", "warning",
                ]))
            wait_for(issuer + "/.well-known/openid-configuration", processes)
            wait_for(origin, processes)
            with httpx.Client(timeout=10, follow_redirects=False) as browser:
                browser.cookies.set(COOKIE_NAME, token, domain="localhost.local", path="/")
                # Keep cookie delivery explicit: never send the issuer cookie to the demo host.
                start = browser.get(origin + "/login")
                assert start.status_code == 302
                authorized = browser.get(start.headers["location"], headers={"Cookie": COOKIE_NAME + "=" + token})
                assert authorized.status_code == 302
                callback = browser.get(authorized.headers["location"])
                assert callback.status_code == 302
                assert browser.get(origin + "/me").json()["sub"] == str(user_id)
                assert browser.get(authorized.headers["location"]).status_code == 400

                verifier = secrets.token_urlsafe(32)
                challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
                grant = browser.get(issuer + "/authorize", params={
                    "response_type": "code", "client_id": client_id, "redirect_uri": origin + "/callback",
                    "scope": "student:eligibility:read", "code_challenge": challenge, "code_challenge_method": "S256",
                }, headers={"Cookie": COOKIE_NAME + "=" + token})
                code = parse_qs(urlsplit(grant.headers["location"]).query)["code"][0]
                exchanged = browser.post(issuer + "/token", data={
                    "grant_type": "authorization_code", "code": code, "redirect_uri": origin + "/callback",
                    "code_verifier": verifier, "client_id": client_id, "client_secret": secret,
                })
                assert exchanged.status_code == 200
                eligibility = browser.get(issuer + "/api/v1/student/eligibility", headers={
                    "Authorization": "Bearer " + exchanged.json()["access_token"],
                })
                assert eligibility.status_code == 200
                assert eligibility.json()["status"] == "eligible" and eligibility.json()["verified"] is False
                credential_headers = {"Origin": issuer, "Cookie": COOKIE_NAME + "=" + token}
                credential = browser.post(issuer + "/api/v1/qr/credentials", headers=credential_headers, json={})
                assert credential.status_code == 200
                assert credential.headers["cache-control"] == "no-store"
                repeated = browser.post(issuer + "/api/v1/qr/credentials", headers=credential_headers)
                assert repeated.json() == credential.json()
                compact = credential.json()["token"]
                decoded = zxingcpp.read_barcode(Image.open(BytesIO(encode_png(compact))))
                assert decoded is not None and decoded.text == compact
                qr_claims = QRValidator(QRSettings(issuer), FileKeyProvider(path)).validate(decoded.text)
                assert qr_claims["cid"] == credential.json()["credential_id"] and "sub" not in qr_claims
                assert browser.post(origin + "/logout", headers={"Origin": origin}).status_code == 204
                assert browser.get(origin + "/me").status_code == 401
                assert browser.get(issuer + "/auth/me", headers={"Cookie": COOKIE_NAME + "=" + token}).status_code == 200
            for process in processes:
                process.terminate()
                process.wait(timeout=10)
            processes.clear()
        print("Live HTTP: Discovery, JWKS, OIDC callback, isolated client session and eligibility passed")
        print("Live HTTP: self-issued static QR, repeat issuance, PNG / ZXing roundtrip and QR signature passed")
    finally:
        for process in processes:
            process.terminate()
            process.wait(timeout=10)
        if token:
            asyncio.run(browser_session(user_id, token))
        with Session(engine) as session:
            client = session.get(SSOClient, client_id)
            if client:
                session.delete(client)
            if user_id and (user := session.get(User, user_id)):
                session.delete(user)
            session.commit()
        with engine.begin() as connection:
            connection.execute(text("DROP SCHEMA public CASCADE"))
            connection.execute(text("CREATE SCHEMA public"))
        engine.dispose()


if __name__ == "__main__":
    main()
