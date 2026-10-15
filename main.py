from contextlib import asynccontextmanager
import os

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from sqlalchemy import text

from database import create_database_engine
from redis_connection import create_redis_client
from auth.session import SessionError, clear_session_cookie
from sso.jwt import JWTIssuer, JWTSettings
from signing_keys import FileKeyProvider
from qr.tokens import QRIssuer, QRSettings

from routes import router
from routes.auth import router as auth_router
from routes.session import router as session_router
from routes.admin import router as admin_router
from routes.clients import router as clients_router
from routes.authorization import router as authorization_router
from routes.token import router as token_router
from routes.oidc import router as oidc_router
from routes.student import router as student_router
from routes.qr import router as qr_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    engine = create_database_engine()
    redis_client = None
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        app.state.database_engine = engine
        redis_client = create_redis_client()
        await redis_client.ping()
        app.state.redis_client = redis_client
        keys = app.state.sso_key_provider
        if keys is None and os.getenv("SIGNING_KEYS_FILE"):
            keys = FileKeyProvider(os.environ["SIGNING_KEYS_FILE"])
        app.state.token_issuer = JWTIssuer(JWTSettings.from_environment(), keys) if keys is not None else None
        app.state.qr_issuer = QRIssuer(QRSettings.from_environment(app.state.token_issuer.settings.issuer), keys) if keys is not None else None
        yield
    finally:
        try:
            if redis_client is not None:
                await redis_client.aclose()
        finally:
            engine.dispose()


app = FastAPI(title="Argus API", lifespan=lifespan)
app.state.token_issuer = None
app.state.sso_key_provider = None
app.state.qr_issuer = None
app.include_router(router)
app.include_router(auth_router)
app.include_router(session_router)
app.include_router(admin_router)
app.include_router(clients_router)
app.include_router(authorization_router)
app.include_router(token_router)
app.include_router(oidc_router)
app.include_router(student_router)
app.include_router(qr_router)


@app.exception_handler(SessionError)
async def session_error_handler(request, error: SessionError):
    response = JSONResponse({"detail": error.detail}, status_code=error.status, headers={"Cache-Control": "no-store"})
    if error.status == 401:
        clear_session_cookie(response)
    return response


@app.get("/")
async def root() -> dict[str, str]:
    return {"message": "Aletheia API is running"}
