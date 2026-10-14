import os

from sqlalchemy import URL, create_engine
from sqlalchemy.engine import Engine


def get_database_url() -> str:
    """Use an explicit URL or build one from the shared PostgreSQL settings."""
    if database_url := os.getenv("DATABASE_URL"):
        return database_url
    required = ("POSTGRES_USER", "POSTGRES_PASSWORD", "POSTGRES_DB", "POSTGRES_HOST")
    missing = [key for key in required if not os.getenv(key)]
    if missing:
        raise RuntimeError("Set DATABASE_URL or these database settings: " + ", ".join(missing))
    return URL.create(
        "postgresql+psycopg",
        username=os.environ["POSTGRES_USER"],
        password=os.environ["POSTGRES_PASSWORD"],
        host=os.environ["POSTGRES_HOST"],
        port=int(os.getenv("POSTGRES_PORT", "5432")),
        database=os.environ["POSTGRES_DB"],
    ).render_as_string(hide_password=False)


def create_database_engine() -> Engine:
    return create_engine(get_database_url(), pool_pre_ping=True, connect_args={"connect_timeout": 5})
