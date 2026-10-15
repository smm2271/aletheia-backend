import base64
import hashlib
import json
import os
import re
import secrets
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from urllib.parse import quote_plus, urlencode, urlsplit

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from redis.asyncio import Redis
from redis.exceptions import RedisError

from signing_keys import raw_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sso.jwt import JWTSettings, JWTValidator

FLOW_COOKIE = "argus_demo_flow"
SESSION_COOKIE = "argus_demo_session"
FLOW_PREFIX = "argus-demo:flow:"
SESSION_PREFIX = "argus-demo:session:"
FLOW_TTL = 300
SESSION_TTL = 3600


@dataclass(frozen=True)
class ClientSettings:
    issuer: str
    client_id: str
    client_secret: str = field(repr=False)
    origin: str = "http://127.0.0.1:8001"
    redis_url: str = field(default="redis://localhost:6380/1", repr=False)

    def __post_init__(self):
        JWTSettings(self.issuer, "unused-by-id-token-validation")
        JWTSettings(self.origin, "unused")
        uri = urlsplit(self.origin)
        uri.port
        if uri.path or not self.client_id or not self.client_secret or self.origin == self.issuer.rstrip("/"):
            raise ValueError("Configure a client ID, secret and separate client origin")
        # Cookies are not isolated by port: use a different hostname from Argus.
        if uri.hostname == urlsplit(self.issuer).hostname:
            raise ValueError("Client and issuer must use separate cookie hostnames")

    @property
    def secure(self):
        return urlsplit(self.origin).scheme == "https"

    @property
    def callback(self):
        return self.origin + "/callback"

    @classmethod
    def from_environment(cls):
        return cls(os.environ["DEMO_ISSUER"], os.environ["DEMO_CLIENT_ID"], os.environ["DEMO_CLIENT_SECRET"],
                   os.getenv("DEMO_PUBLIC_ORIGIN", "http://127.0.0.1:8001"), os.environ["DEMO_REDIS_URL"])


def fingerprint(token):
    if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", token):
        return None
    return hashlib.sha256(token.encode("ascii")).hexdigest()


class PublicKeys:
    def __init__(self, document):
        try:
            self.keys = {}
            if not isinstance(document["keys"], list) or not document["keys"]:
                raise ValueError()
            for key in document["keys"]:
                if (key.get("kty") != "OKP" or key.get("crv") != "Ed25519" or key.get("alg") != "EdDSA"
                        or key.get("use") != "sig" or "d" in key or not isinstance(key.get("kid"), str)
                        or not key["kid"] or key["kid"] in self.keys):
                    raise ValueError()
                self.keys[key["kid"]] = Ed25519PublicKey.from_public_bytes(raw_key(key["x"]))
        except (KeyError, TypeError, ValueError, AttributeError):
            raise ValueError("Invalid issuer public keys") from None

    def verification_key(self, purpose, kid):
        return self.keys.get(kid) if purpose == "sso" else None


async def metadata(http, settings):
    base = settings.issuer.rstrip("/")
    response = await http.get(base + "/.well-known/openid-configuration")
    response.raise_for_status()
    document = response.json()
    if (document.get("issuer") != settings.issuer
            or any(document.get(k) != base + suffix for k, suffix in (
                ("authorization_endpoint", "/authorize"), ("token_endpoint", "/token"),
                ("jwks_uri", "/.well-known/jwks.json")))
            or "EdDSA" not in document.get("id_token_signing_alg_values_supported", [])
            or "S256" not in document.get("code_challenge_methods_supported", [])):
        raise ValueError("Unexpected issuer metadata")
    return document


def create_app(settings: ClientSettings | None = None) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app):
        config = settings or ClientSettings.from_environment()
        store = Redis.from_url(config.redis_url, decode_responses=True, socket_connect_timeout=3, socket_timeout=3)
        try:
            await store.ping()
            async with httpx.AsyncClient(timeout=10, follow_redirects=False) as http:
                app.state.settings, app.state.store, app.state.http = config, store, http
                yield
        finally:
            await store.aclose()

    app = FastAPI(title="Argus demonstration client", lifespan=lifespan)

    @app.middleware("http")
    async def no_cache(request, call_next):
        response = await call_next(request)
        response.headers.update({"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"})
        return response

    @app.exception_handler(RedisError)
    async def unavailable(request, error):
        return JSONResponse({"detail": "Client session store unavailable"}, status_code=503)

    @app.get("/", response_class=HTMLResponse)
    async def home():
        return '<h1>Argus SSO Demo</h1><p><a href="/login">Login with Argus</a></p><p><a href="/me">Login result</a></p>'

    @app.get("/login")
    async def login(request: Request):
        config, store = request.app.state.settings, request.app.state.store
        try:
            document = await metadata(request.app.state.http, config)
        except (httpx.HTTPError, ValueError, TypeError, AttributeError):
            raise HTTPException(502, "Issuer discovery unavailable") from None
        state, nonce, browser, verifier = (secrets.token_urlsafe(32) for _ in range(4))
        record = {"state": state, "nonce": nonce, "verifier": verifier, "expires_at": int(time.time()) + FLOW_TTL}
        previous = fingerprint(request.cookies.get(FLOW_COOKIE))
        if previous:
            await store.delete(FLOW_PREFIX + previous)
        await store.set(FLOW_PREFIX + fingerprint(browser), json.dumps(record), ex=FLOW_TTL)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode()
        response = RedirectResponse(document["authorization_endpoint"] + "?" + urlencode({
            "response_type": "code", "client_id": config.client_id, "redirect_uri": config.callback,
            "scope": "openid", "state": state, "nonce": nonce,
            "code_challenge": challenge, "code_challenge_method": "S256",
        }), status_code=302)
        response.set_cookie(FLOW_COOKIE, browser, max_age=FLOW_TTL, httponly=True, secure=config.secure, samesite="lax")
        return response

    @app.get("/callback")
    async def callback(request: Request):
        config, store, http = request.app.state.settings, request.app.state.store, request.app.state.http
        try:
            browser = fingerprint(request.cookies.get(FLOW_COOKIE))
            if browser is None:
                raise ValueError()
            record = json.loads(await store.getdel(FLOW_PREFIX + browser))
            query = request.query_params
            if (set(query) - {"code", "state", "error", "error_description", "iss"}
                    or any(len(query.getlist(k)) != 1 for k in query)
                    or not secrets.compare_digest(query.get("state", ""), record["state"])
                    or record["expires_at"] <= int(time.time()) or "error" in query
                    or not query.get("code") or len(query["code"]) > 512
                    or ("iss" in query and query["iss"] != config.issuer)):
                raise ValueError()
            document = await metadata(http, config)
            credentials = quote_plus(config.client_id) + ":" + quote_plus(config.client_secret)
            auth = base64.b64encode(credentials.encode()).decode()
            response = await http.post(document["token_endpoint"], data={
                "grant_type": "authorization_code", "code": query["code"], "redirect_uri": config.callback,
                "code_verifier": record["verifier"],
            }, headers={"Authorization": "Basic " + auth})
            response.raise_for_status()
            body = response.json()
            public = await http.get(document["jwks_uri"])
            public.raise_for_status()
            validator = JWTValidator(JWTSettings(config.issuer, "unused", id_ttl=3600), PublicKeys(public.json()))
            identity = validator.validate_id_token(body["id_token"], client_id=config.client_id, nonce=record["nonce"])
            token = secrets.token_urlsafe(32)
            await store.set(SESSION_PREFIX + fingerprint(token), json.dumps({
                "sub": identity["sub"], "expires_at": int(time.time()) + SESSION_TTL,
            }), ex=SESSION_TTL)
            previous = fingerprint(request.cookies.get(SESSION_COOKIE))
            if previous:
                await store.delete(SESSION_PREFIX + previous)
            result = RedirectResponse("/me", status_code=302)
            result.set_cookie(SESSION_COOKIE, token, max_age=SESSION_TTL, httponly=True, secure=config.secure, samesite="lax")
        except (ValueError, TypeError, KeyError, AttributeError, httpx.HTTPError):
            result = JSONResponse({"detail": "OIDC login failed"}, status_code=400)
        result.delete_cookie(FLOW_COOKIE, httponly=True, secure=config.secure, samesite="lax")
        return result

    @app.get("/me")
    async def me(request: Request):
        identifier = fingerprint(request.cookies.get(SESSION_COOKIE))
        try:
            if identifier is None:
                raise ValueError()
            record = json.loads(await request.app.state.store.get(SESSION_PREFIX + identifier))
            if record["expires_at"] <= int(time.time()):
                raise ValueError()
            return {"authenticated": True, "sub": record["sub"]}
        except (ValueError, TypeError, KeyError):
            raise HTTPException(401, "Not logged in") from None

    @app.post("/logout", status_code=204)
    async def logout(request: Request):
        config = request.app.state.settings
        if request.headers.get("origin") != config.origin:
            raise HTTPException(403, "Invalid request origin")
        identifier = fingerprint(request.cookies.get(SESSION_COOKIE))
        if identifier:
            await request.app.state.store.delete(SESSION_PREFIX + identifier)
        result = Response(status_code=204)
        result.delete_cookie(SESSION_COOKIE, httponly=True, secure=config.secure, samesite="lax")
        return result

    return app


app = create_app()
