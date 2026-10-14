from contextlib import asynccontextmanager

from fastapi import FastAPI
from sqlalchemy import text

from database import create_database_engine

from routes import router
from routes.auth import router as auth_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    engine = create_database_engine()
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        app.state.database_engine = engine
        yield
    finally:
        engine.dispose()


app = FastAPI(title="Aletheia API", lifespan=lifespan)
app.include_router(router)
app.include_router(auth_router)


@app.get("/")
async def root() -> dict[str, str]:
    return {"message": "Aletheia API is running"}
