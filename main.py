from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from sqlalchemy import text

from database import create_database_engine
from redis_connection import create_redis_client
from auth.session import SessionError, clear_session_cookie

from routes import router
from routes.auth import router as auth_router
from routes.session import router as session_router


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
        yield
    finally:
        try:
            if redis_client is not None:
                await redis_client.aclose()
        finally:
            engine.dispose()


app = FastAPI(title="Aletheia API", lifespan=lifespan)
app.include_router(router)
app.include_router(auth_router)
app.include_router(session_router)


@app.exception_handler(SessionError)
async def session_error_handler(request, error: SessionError):
    response = JSONResponse({"detail": error.detail}, status_code=error.status, headers={"Cache-Control": "no-store"})
    if error.status == 401:
        clear_session_cookie(response)
    return response


@app.get("/")
async def root() -> dict[str, str]:
    return {"message": "Aletheia API is running"}
