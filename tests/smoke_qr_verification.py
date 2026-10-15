"""Isolated real HTTP QR verification smoke; never contacts external Google.

Requires a dedicated empty TEST_DATABASE_URL and a dedicated TEST_REDIS_URL.
Reuses the established session provisioning and Uvicorn readiness helpers.
"""
import asyncio
import base64
import hashlib
import os
import secrets
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import httpx
from redis import Redis
from alembic import command
from alembic.config import Config
from sqlalchemy import inspect, text
from sqlalchemy.orm import Session

from auth.session import COOKIE_NAME
from database import create_database_engine
from models import Affiliation, ClientType, SSOClient, TrustLevel, User
from qr.nonces import NONCE_NAMESPACE, generate_nonce
from redis_connection import create_redis_client
from signing_keys import KeyRing, SigningKey, save_key_file
from smoke_oidc import browser_session, wait_for
from sso.clients import hash_secret


def main():
    issuer = "http://localhost:18002"
    scope = "qr:static:verify"
    os.environ.update({
        "DATABASE_URL": os.environ["TEST_DATABASE_URL"], "REDIS_URL": os.environ["TEST_REDIS_URL"],
        "SESSION_PUBLIC_ORIGIN": issuer, "SESSION_COOKIE_SECURE": "false",
        "SSO_ISSUER": issuer, "SSO_ACCESS_AUDIENCE": "argus-api",
    })
    engine = create_database_engine()
    assert not inspect(engine).get_table_names(), "Smoke requires a dedicated empty PostgreSQL database"
    processes, sessions, nonces = [], [], []
    client_id, secret = "qr-smoke-" + secrets.token_hex(8), secrets.token_urlsafe(32)
    callback = "https://scanner.example/callback"
    try:
        command.upgrade(Config("alembic.ini"), "head")
        with Session(engine) as db:
            holder = User(email=client_id + "-holder@example.edu", affiliation=Affiliation.STUDENT)
            scanner = User(email=client_id + "-scanner@example.edu", affiliation=Affiliation.STUDENT)
            db.add_all([holder, scanner])
            db.flush()
            holder_id, scanner_id = holder.id, scanner.id
            db.add(SSOClient(client_id=client_id, name="QR scanner smoke", client_type=ClientType.CONFIDENTIAL,
                             trust_level=TrustLevel.FIRST_PARTY, enabled=True, secret_hash=hash_secret(secret),
                             redirect_uris=[callback], allowed_scopes=[scope]))
            db.commit()
        for user_id in (holder_id, scanner_id):
            sessions.append((user_id, asyncio.run(browser_session(user_id))))
        with tempfile.TemporaryDirectory() as directory:
            keys = Path(directory) / "keys.json"
            save_key_file(keys, KeyRing([SigningKey.generate("sso"), SigningKey.generate("qr")]), create=True)
            os.environ["SIGNING_KEYS_FILE"] = str(keys)
            processes.append(subprocess.Popen([
                sys.executable, "-m", "uvicorn", "main:app", "--host", "127.0.0.1", "--port", "18002",
                "--no-access-log", "--log-level", "warning",
            ]))
            wait_for(issuer + "/.well-known/openid-configuration", processes)
            with httpx.Client(timeout=15, follow_redirects=False) as browser:
                issued = browser.post(issuer + "/api/v1/qr/credentials", headers={
                    "Cookie": COOKIE_NAME + "=" + sessions[0][1], "Origin": issuer,
                }, json={})
                assert issued.status_code == 200
                qr = issued.json()["token"]
                verifier = secrets.token_urlsafe(32)
                challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
                authorized = browser.get(issuer + "/authorize", params={
                    "response_type": "code", "client_id": client_id, "redirect_uri": callback, "scope": scope,
                    "code_challenge": challenge, "code_challenge_method": "S256",
                }, headers={"Cookie": COOKIE_NAME + "=" + sessions[1][1]})
                assert authorized.status_code == 302
                code = parse_qs(urlsplit(authorized.headers["location"]).query)["code"][0]
                exchanged = browser.post(issuer + "/token", data={
                    "grant_type": "authorization_code", "client_id": client_id, "client_secret": secret,
                    "code": code, "redirect_uri": callback, "code_verifier": verifier,
                })
                assert exchanged.status_code == 200
                access = exchanged.json()["access_token"]
                headers = {"Authorization": "Bearer " + access}
                endpoint = issuer + "/api/v1/qr/static/verify"
                nonce = generate_nonce()
                nonces.append(nonce)
                payload = {"token": qr, "nonce": nonce}
                assert browser.post(endpoint, json=payload).status_code == 401
                accepted = browser.post(endpoint, headers=headers, json=payload)
                assert accepted.status_code == 200 and accepted.json() == {"valid": True}
                assert accepted.headers["cache-control"] == "no-store"
                assert browser.post(endpoint, headers=headers, json=payload).status_code == 409
                fresh = generate_nonce()
                nonces.append(fresh)
                assert browser.post(endpoint, headers=headers, json={"token": qr, "nonce": fresh}).status_code == 200
                # Actual concurrent HTTP requests, sharing only the signed inputs.
                raced = {"token": qr, "nonce": generate_nonce()}
                nonces.append(raced["nonce"])
                def submit(_):
                    return httpx.post(endpoint, headers=headers, json=raced, timeout=15).status_code
                with ThreadPoolExecutor(max_workers=8) as pool:
                    statuses = list(pool.map(submit, range(8)))
                assert statuses.count(200) == 1 and statuses.count(409) == 7
                # Exercise the real Redis socket failure path, rather than a mock.
                # Redis resumes automatically; this smoke owns its Redis instance.
                unavailable_nonce = generate_nonce()
                nonces.append(unavailable_nonce)
                paused_at = time.monotonic()
                with Redis.from_url(os.environ["TEST_REDIS_URL"], socket_timeout=15) as control:
                    control.execute_command("CLIENT", "PAUSE", 6000, "WRITE")
                try:
                    unavailable = browser.post(endpoint, headers=headers, json={"token": qr, "nonce": unavailable_nonce})
                    assert unavailable.status_code == 503
                    assert unavailable.headers["cache-control"] == "no-store"
                finally:
                    # A timed-out SET can still commit. Wait before session/key cleanup.
                    while time.monotonic() - paused_at < 6.2:
                        time.sleep(0.1)
                recovered_nonce = generate_nonce()
                nonces.append(recovered_nonce)
                assert browser.post(endpoint, headers=headers, json={"token": qr, "nonce": recovered_nonce}).status_code == 200
                assert browser.get(issuer + "/auth/me", headers={"Cookie": COOKIE_NAME + "=" + sessions[0][1]}).json()["user"]["id"] == str(holder_id)
            print("Live HTTP QR: holder issuance, scanner code exchange, minimal verification, replay, fresh nonce, atomic race and real Redis write outage passed")
    finally:
        for process in processes:
            process.terminate()
            process.wait(timeout=10)
        for user_id, token in sessions:
            asyncio.run(browser_session(user_id, token))
        async def cleanup_nonces():
            redis = create_redis_client()
            try:
                keys = [f"{NONCE_NAMESPACE}:{hashlib.sha256(client_id.encode()).hexdigest()}:"
                        f"{hashlib.sha256(nonce.encode('ascii')).hexdigest()}" for nonce in nonces]
                if keys:
                    await redis.delete(*keys)
            finally:
                await redis.aclose()
        asyncio.run(cleanup_nonces())
        with engine.begin() as connection:
            connection.execute(text("DROP SCHEMA public CASCADE"))
            connection.execute(text("CREATE SCHEMA public"))
        engine.dispose()


if __name__ == "__main__":
    main()
