"""Live W10 acceptance, invoked by smoke_qr_verification.py on its isolated services."""

import os
import time
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import jwt
from redis import Redis

from auth.session import COOKIE_NAME
from qr.dynamic_state import state_key


def dynamic_smoke(browser, issuer, holder_session, scanner_session, headers):
    root = issuer + "/api/v1/qr/dynamic"
    holder = {"Origin": issuer, "Cookie": COOKIE_NAME + "=" + holder_session}
    keys = []

    def issue():
        response = browser.post(root + "/issue", headers=holder)
        assert response.status_code == 200
        body = response.json()
        assert body["refresh_after"] == 25 and body["token_type"] == "aletheia.qr.dynamic"
        claims = jwt.decode(body["token"], options={"verify_signature": False})  # Cleanup only.
        assert claims["exp"] - claims["iat"] == 30
        keys.append(state_key(claims["jti"]))
        return body["token"]

    with Redis.from_url(os.environ["TEST_REDIS_URL"], decode_responses=True, socket_timeout=15) as control:
        try:
            token = issue()
            replacement = issue()
            assert token != replacement
            assert browser.post(root + "/verify", json={"token": token}).status_code == 401
            gate = Barrier(101, timeout=15)

            def scan():
                gate.wait()
                response = browser.post(root + "/verify", headers=headers, json={"token": token})
                assert response.status_code == 200
                assert response.headers["cache-control"] == "no-store"
                return response.json()

            with ThreadPoolExecutor(max_workers=100) as pool:
                futures = [pool.submit(scan) for _ in range(100)]
                try:
                    # Fresh token immediately before releasing all 100 HTTP workers.
                    token = issue()
                    race_key = keys[-1]
                    expires = int(control.hget(race_key, "exp"))
                    started = time.monotonic()
                    gate.wait()
                    results = [future.result(timeout=15) for future in futures]
                finally:
                    gate.abort()
            elapsed = time.monotonic() - started
            assert elapsed < 15
            assert control.time()[0] < expires, "Race must finish before token expiry"
            assert results.count({"valid": True}) == 1
            assert results.count({"valid": False}) == 99
            assert control.hget(race_key, "state") == "CONSUMED"
            print(f"Dynamic QR synchronized HTTP race: workers=100, completed=100, valid=1, invalid=99, "
                  f"state=CONSUMED, elapsed={elapsed:.3f}s, before_expiry=true")
            assert browser.post(root + "/revoke", headers={"Origin": issuer, "Cookie": COOKIE_NAME + "=" + scanner_session},
                                json={"token": replacement}).status_code == 403
            assert browser.post(root + "/revoke", headers=holder, json={"token": replacement}).json() == {"revoked": True}
            assert browser.post(root + "/verify", headers=headers, json={"token": replacement}).json() == {"valid": False}
            # Real socket timeout, including uncertain delivery of the atomic consume.
            uncertain = issue()
            paused_at = time.monotonic()
            control.execute_command("CLIENT", "PAUSE", 6000, "WRITE")
            try:
                response = browser.post(root + "/verify", headers=headers, json={"token": uncertain})
                assert response.status_code == 503 and response.headers["cache-control"] == "no-store"
            finally:
                while time.monotonic() - paused_at < 6.2:
                    time.sleep(0.1)
            # Never claim the uncertain token succeeded; a new token can prove recovery.
            recovered = issue()
            assert browser.post(root + "/verify", headers=headers, json={"token": recovered}).json() == {"valid": True}
            print("Live HTTP dynamic QR: distinct holder/scanner, rotation, 100 concurrent scans, revocation, ownership and real Redis timeout/recovery passed")
        finally:
            if keys:
                control.delete(*keys)
